"""Shared Phase 5 execution service.

All interactive multi-model work uses the application's existing
ProviderRouter.  The service deliberately emits lifecycle events rather than
pretending that a provider supports token streaming when its client does not.
"""

import asyncio
import time
from datetime import datetime, timezone
from typing import Any

from agents.providers.provider_router import ModelRequest
from agents.providers.clients.base import StreamEventType
from app.db.session import AsyncSessionLocal
from sqlalchemy import select

_subscribers: dict[str, set[asyncio.Queue]] = {}


async def publish(run_id: str, event: dict[str, Any]) -> None:
    for queue in list(_subscribers.get(run_id, set())):
        await queue.put(event)


async def events(run_id: str, replay: list[dict] | None = None):
    """
    Subscribe to live events for `run_id`. To avoid the race where a
    client's POST /run starts a background task that finishes emitting
    events before the client's GET /stream call subscribes (losing every
    token in between — the events dict only fans out to queues that exist
    *at publish time*), the caller can pass `replay`: a snapshot of
    already-known state (e.g. "this response is already complete, here's
    its content") to send immediately after subscribing and before
    draining live events. Subscribing happens before computing the
    replay snapshot isn't required here since the caller queries the
    snapshot before calling this generator; the remaining, much smaller
    race (an event published between the caller's snapshot query and
    this function registering its queue) is inherent to any pull-based
    reconnect and is not solved by this alone — see docs/PHASE5 note.
    """
    queue: asyncio.Queue = asyncio.Queue()
    _subscribers.setdefault(run_id, set()).add(queue)
    try:
        yield {"type": "connected", "run_id": run_id}
        for ev in replay or []:
            yield ev
        while True:
            try:
                yield await asyncio.wait_for(queue.get(), timeout=15)
            except asyncio.TimeoutError:
                yield {"type": "keepalive"}
    finally:
        _subscribers.get(run_id, set()).discard(queue)


async def replay_snapshot(
    response_model: Any, parent_id_field: str, run_id: str
) -> list[dict]:
    """Build synthetic events reflecting each response's current DB state,
    for a client that connects to /stream after execution already began
    (or even after it finished) — closes the SSE race/lost-token gap."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(response_model).where(
                getattr(response_model, parent_id_field) == run_id
            )
        )
        records = result.scalars().all()

    snapshot: list[dict] = []
    for record in records:
        base = {
            "response_id": str(record.id),
            "provider": record.provider,
            "model": record.model,
        }
        if record.status == "completed":
            snapshot.append(
                {
                    "type": "model_completed",
                    **base,
                    "content": record.content,
                    "latency_ms": record.latency_ms,
                    "tokens_prompt": record.tokens_prompt,
                    "tokens_completion": record.tokens_completion,
                    "estimated_cost_usd": record.estimated_cost_usd,
                    "replayed": True,
                }
            )
        elif record.status == "error":
            snapshot.append(
                {"type": "model_error", **base, "error": record.error, "replayed": True}
            )
        elif record.status == "stopped":
            snapshot.append(
                {
                    "type": "model_stopped",
                    **base,
                    "content": record.content,
                    "replayed": True,
                }
            )
        elif record.status == "streaming":
            # Still in progress: replay what's been persisted so far as one
            # token event, then live queue events continue it from here.
            snapshot.append(
                {
                    "type": "model_token",
                    **base,
                    "chunk": "",
                    "content": record.content,
                    "replayed": True,
                }
            )
    return snapshot


async def execute_models(
    *,
    run_id: str,
    response_model: Any,
    parent_model: Any,
    parent_id_field: str,
    configs: list[dict],
    prompt: str,
    temperature: float,
    max_tokens: int,
    router: Any,
    agent_type: str
) -> None:
    """Stream selected models concurrently, persist chunks, and isolate failures."""

    async def run_one(config: dict) -> None:
        provider, model = config.get("provider"), config.get("model")
        async with AsyncSessionLocal() as db:
            explicit_id = config.get("response_id")
            if explicit_id:
                # Preferred path: the caller already knows exactly which
                # row this is (run_session/run_battle create the row and
                # know its id before calling execute_models; regenerate
                # knows the id the user clicked "regenerate" on). Avoids
                # the ambiguous provider+model+status="streaming" lookup
                # below ever picking the wrong row when more than one
                # response for the same run shares a provider+model, or
                # when a regenerate races with another streaming response.
                result = await db.execute(
                    select(response_model).where(response_model.id == explicit_id)
                )
            else:
                result = await db.execute(
                    select(response_model)
                    .where(
                        getattr(response_model, parent_id_field) == run_id,
                        response_model.provider == provider,
                        response_model.model == model,
                        response_model.status == "streaming",
                    )
                    .order_by(response_model.created_at.desc())
                    .limit(1)
                )
            record = result.scalar_one_or_none()
            if record is None:
                return
            await publish(
                run_id,
                {
                    "type": "model_started",
                    "response_id": str(record.id),
                    "provider": provider,
                    "model": model,
                },
            )
            started = time.monotonic()
            stopped_mid_stream = False
            try:
                content, usage = "", {}
                stream = router.stream(
                    ModelRequest(
                        provider=provider,
                        model=model,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        agent_type=agent_type,
                        messages=[{"role": "user", "content": prompt}],
                    )
                )
                async for event in stream:
                    if event.type == StreamEventType.TOKEN:
                        # Check for a concurrent POST /stop *before*
                        # applying/publishing this chunk — not after, or a
                        # chunk that arrived post-stop (but was already
                        # in flight from the provider) would still get
                        # persisted and broadcast once before the loop
                        # noticed. Only the `status` column is refreshed,
                        # not the whole row, so it doesn't clobber the
                        # `content` accumulated locally.
                        await db.refresh(record, attribute_names=["status"])
                        if record.status == "stopped":
                            stopped_mid_stream = True
                            await stream.aclose()
                            break
                        chunk = str(event.data or "")
                        if not chunk:
                            continue
                        content += chunk
                        record.content = content
                        # Persist every chunk so reconnecting clients can recover output.
                        await db.commit()
                        await publish(
                            run_id,
                            {
                                "type": "model_token",
                                "response_id": str(record.id),
                                "provider": provider,
                                "model": model,
                                "chunk": chunk,
                                "content": content,
                            },
                        )
                    elif event.type == StreamEventType.ERROR:
                        raise RuntimeError(
                            str(event.data or "provider streaming error")
                        )
                    elif event.type == StreamEventType.COMPLETE:
                        usage = (event.metadata or {}).get("usage") or {}
                if stopped_mid_stream:
                    # `status`/`updated_at` are already "stopped" (set by
                    # the /stop endpoint); persist the partial content
                    # captured up to the stop point and emit a distinct
                    # event so the client knows generation was cut off
                    # here rather than completing normally.
                    record.content = content
                    await db.commit()
                    await publish(
                        run_id,
                        {
                            "type": "model_stopped",
                            "response_id": str(record.id),
                            "provider": provider,
                            "model": model,
                            "content": content,
                        },
                    )
                    return
                await db.refresh(record)
                if record.status == "stopped":
                    return
                record.content = content
                record.tokens_prompt = usage.get("prompt_tokens") or usage.get(
                    "input_tokens"
                )
                record.tokens_completion = usage.get("completion_tokens") or usage.get(
                    "output_tokens"
                )
                record.estimated_cost_usd = usage.get("estimated_cost_usd")
                record.latency_ms = (time.monotonic() - started) * 1000
                record.status = "completed"
                await db.commit()
                await publish(
                    run_id,
                    {
                        "type": "model_completed",
                        "response_id": str(record.id),
                        "provider": provider,
                        "model": model,
                        "content": record.content,
                        "latency_ms": record.latency_ms,
                        "tokens_prompt": record.tokens_prompt,
                        "tokens_completion": record.tokens_completion,
                        "estimated_cost_usd": record.estimated_cost_usd,
                    },
                )
            except Exception as exc:  # a single provider must not end the run
                record.status, record.error = "error", str(exc)[:2000]
                record.latency_ms = (time.monotonic() - started) * 1000
                await db.commit()
                await publish(
                    run_id,
                    {
                        "type": "model_error",
                        "response_id": str(record.id),
                        "provider": provider,
                        "model": model,
                        "error": record.error,
                    },
                )

    await asyncio.gather(*(run_one(c) for c in configs), return_exceptions=True)
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(parent_model).where(parent_model.id == run_id))
        parent = result.scalar_one_or_none()
        if parent and parent.status == "running":
            # Reflect what actually happened to each model, not just "did
            # the run finish" — a run where every model errored out is not
            # "completed" in any useful sense, and a run where some
            # succeeded and some failed shouldn't look identical to one
            # where everything succeeded.
            status_result = await db.execute(
                select(response_model.status).where(
                    getattr(response_model, parent_id_field) == run_id
                )
            )
            child_statuses = [row[0] for row in status_result.all()]
            succeeded = sum(1 for s in child_statuses if s == "completed")
            failed = sum(1 for s in child_statuses if s == "error")
            stopped = sum(1 for s in child_statuses if s == "stopped")

            if stopped and not succeeded and not failed:
                final_status = "stopped"
            elif succeeded == 0 and failed > 0:
                final_status = "failed"
            elif failed > 0 or stopped > 0:
                final_status = "partial"
            else:
                final_status = "completed"

            parent.status, parent.completed_at = final_status, datetime.now(
                timezone.utc
            )
            await db.commit()
    await publish(run_id, {"type": "run_completed", "run_id": run_id})
