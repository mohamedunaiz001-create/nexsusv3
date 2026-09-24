"""
Playground API endpoints - Phase 5.

Handles multi-model AI playground sessions, file uploads, and streaming responses.
"""

from datetime import datetime, timezone
import asyncio
import json
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import select, delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from app.core.exceptions import NotFoundError
from app.core.security import get_current_user_id_optional
from app.db.session import get_db
from app.schemas.common import APIResponse

router = APIRouter(prefix="/playground", tags=["playground"])


# ─── Schemas ──────────────────────────────────────────────────────────────


class PlaygroundSessionCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    prompt: str
    model_configs: List[Dict[str, Any]] = Field(..., min_length=1, max_length=8)
    temperature: float = Field(0.7, ge=0.0, le=2.0)
    max_tokens: int = Field(2000, ge=1, le=8192)
    file_ids: List[str] = Field(default_factory=list)


class PlaygroundSessionUpdate(BaseModel):
    name: Optional[str] = None
    prompt: Optional[str] = None
    model_configs: Optional[List[Dict[str, Any]]] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None


class PlaygroundSessionResponse(BaseModel):
    id: str
    name: str
    prompt: str
    model_configs: List[Dict[str, Any]]
    temperature: float
    max_tokens: int
    file_ids: List[str]
    status: str
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None


class PlaygroundResponseResponse(BaseModel):
    id: str
    session_id: str
    provider: str
    model: str
    content: str
    structured: Optional[Dict[str, Any]] = None
    tokens_prompt: Optional[int] = None
    tokens_completion: Optional[int] = None
    latency_ms: Optional[float] = None
    estimated_cost_usd: Optional[float] = None
    status: str
    error: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class PlaygroundSessionListResponse(BaseModel):
    id: str
    name: str
    prompt: str
    model_count: int
    status: str
    created_at: datetime
    updated_at: datetime


# ─── Helper functions ───────────────────────────────────────────────────


async def _get_session_or_404(db: AsyncSession, session_id: str):
    from app.models.playground_session import PlaygroundSession

    result = await db.execute(
        select(PlaygroundSession).where(PlaygroundSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise NotFoundError(f"Playground session {session_id} not found")
    return session


# ─── Session CRUD ───────────────────────────────────────────────────────


@router.post(
    "",
    response_model=APIResponse[PlaygroundSessionResponse],
    status_code=status.HTTP_201_CREATED,
)
async def create_session(
    payload: PlaygroundSessionCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    from app.core.model_validation import validate_model_configs

    await validate_model_configs(
        request.app.state.orchestrator.ceo.router, payload.model_configs
    )

    from app.models.playground_session import PlaygroundSession

    session = PlaygroundSession(
        name=payload.name,
        prompt=payload.prompt,
        model_configs=payload.model_configs,
        temperature=payload.temperature,
        max_tokens=payload.max_tokens,
        file_ids=payload.file_ids,
        status="created",
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return APIResponse(data=session, message="Playground session created")


@router.get("", response_model=APIResponse[List[PlaygroundSessionListResponse]])
async def list_sessions(
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
    offset: int = 0,
):
    from app.models.playground_session import PlaygroundSession

    result = await db.execute(
        select(PlaygroundSession)
        .order_by(PlaygroundSession.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    sessions = list(result.scalars().all())
    return APIResponse(
        data=[
            PlaygroundSessionListResponse(
                id=s.id,
                name=s.name,
                prompt=s.prompt[:100] + ("..." if len(s.prompt) > 100 else ""),
                model_count=len(s.model_configs),
                status=s.status,
                created_at=s.created_at,
                updated_at=s.updated_at,
            )
            for s in sessions
        ],
        message=f"{len(sessions)} session(s)",
    )


@router.get("/{session_id}", response_model=APIResponse[PlaygroundSessionResponse])
async def get_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    session = await _get_session_or_404(db, session_id)
    return APIResponse(data=session, message="ok")


@router.patch("/{session_id}", response_model=APIResponse[PlaygroundSessionResponse])
async def update_session(
    session_id: str,
    payload: PlaygroundSessionUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    session = await _get_session_or_404(db, session_id)
    update_data = payload.model_dump(exclude_unset=True)
    if update_data.get("model_configs"):
        from app.core.model_validation import validate_model_configs

        await validate_model_configs(
            request.app.state.orchestrator.ceo.router, update_data["model_configs"]
        )
    for field, value in update_data.items():
        setattr(session, field, value)
    await db.commit()
    await db.refresh(session)
    return APIResponse(data=session, message="Session updated")


@router.delete("/{session_id}", response_model=APIResponse[dict])
async def delete_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    from app.models.playground_response import PlaygroundResponse

    session = await _get_session_or_404(db, session_id)
    await db.execute(
        delete(PlaygroundResponse).where(PlaygroundResponse.session_id == session_id)
    )
    await db.delete(session)
    await db.commit()
    return APIResponse(data={"deleted": session_id}, message="Session deleted")


# ─── Session Execution ───────────────────────────────────────────────────


@router.post("/{session_id}/run", response_model=APIResponse[dict])
async def run_session(
    session_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user_id: str | None = Depends(get_current_user_id_optional),
):
    session = await _get_session_or_404(db, session_id)

    if session.status in ("running", "completed"):
        return APIResponse(
            data={"error": "Session already running or completed"},
            message="Cannot run session",
            success=False,
        )

    session.status = "running"
    await db.commit()

    from app.models.playground_response import PlaygroundResponse

    responses = []
    for config in session.model_configs:
        resp = PlaygroundResponse(
            session_id=session.id,
            provider=config["provider"],
            model=config["model"],
            content="",
            status="streaming",
        )
        db.add(resp)
        responses.append(resp)

    await db.commit()

    from app.core.model_execution import execute_models
    from app.core.evidence import evidence_context
    from app.models.playground_session import PlaygroundSession

    asyncio.create_task(
        execute_models(
            run_id=str(session.id),
            response_model=PlaygroundResponse,
            parent_model=PlaygroundSession,
            parent_id_field="session_id",
            configs=[
                {
                    "provider": resp.provider,
                    "model": resp.model,
                    "response_id": str(resp.id),
                }
                for resp in responses
            ],
            prompt=session.prompt + await evidence_context(db, session.file_ids, current_user_id),
            temperature=session.temperature,
            max_tokens=session.max_tokens,
            router=request.app.state.orchestrator.ceo.router,
            agent_type="playground",
        )
    )

    return APIResponse(
        data={
            "session_id": session.id,
            "response_ids": [r.id for r in responses],
            "message": "Session started, connect to SSE for streaming",
        },
        message="Session running",
    )


@router.post("/{session_id}/stop", response_model=APIResponse[dict])
async def stop_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    from app.models.playground_response import PlaygroundResponse

    session = await _get_session_or_404(db, session_id)

    await db.execute(
        update(PlaygroundResponse)
        .where(
            PlaygroundResponse.session_id == session_id,
            PlaygroundResponse.status == "streaming",
        )
        .values(status="stopped", updated_at=datetime.now(timezone.utc))
    )

    session.status = "stopped"
    session.completed_at = datetime.now(timezone.utc)
    await db.commit()

    return APIResponse(data={"stopped": session_id}, message="Session stopped")


# ─── Streaming endpoint ──────────────────────────────────────────────────


@router.get("/{session_id}/stream")
async def stream_session(
    session_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    from fastapi.responses import StreamingResponse

    from app.models.playground_response import PlaygroundResponse

    # Validates the session exists (404s otherwise).
    await _get_session_or_404(db, session_id)

    async def event_generator():
        from app.core.model_execution import events, replay_snapshot

        snapshot = await replay_snapshot(PlaygroundResponse, "session_id", session_id)
        async for event in events(session_id, replay=snapshot):
            yield f"data: {json.dumps(event, default=str)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ─── Response management ─────────────────────────────────────────────────


@router.get(
    "/{session_id}/responses",
    response_model=APIResponse[List[PlaygroundResponseResponse]],
)
async def list_responses(
    session_id: str,
    db: AsyncSession = Depends(get_db),
):
    await _get_session_or_404(db, session_id)

    from app.models.playground_response import PlaygroundResponse

    result = await db.execute(
        select(PlaygroundResponse)
        .where(PlaygroundResponse.session_id == session_id)
        .order_by(PlaygroundResponse.created_at)
    )
    responses = list(result.scalars().all())
    return APIResponse(data=responses, message=f"{len(responses)} response(s)")


@router.post(
    "/{session_id}/responses/{response_id}/regenerate", response_model=APIResponse[dict]
)
async def regenerate_response(
    session_id: str,
    response_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user_id: str | None = Depends(get_current_user_id_optional),
):
    session = await _get_session_or_404(db, session_id)

    from app.models.playground_response import PlaygroundResponse

    result = await db.execute(
        select(PlaygroundResponse).where(PlaygroundResponse.id == response_id)
    )
    resp = result.scalar_one_or_none()
    if resp is None:
        raise NotFoundError(f"Response {response_id} not found")

    resp.content = ""
    resp.status = "streaming"
    resp.error = None
    resp.updated_at = datetime.now(timezone.utc)
    await db.commit()

    from app.core.evidence import evidence_context
    from app.core.model_execution import execute_models
    from app.models.playground_session import PlaygroundSession

    asyncio.create_task(
        execute_models(
            run_id=str(session.id),
            response_model=PlaygroundResponse,
            parent_model=PlaygroundSession,
            parent_id_field="session_id",
            configs=[
                {
                    "provider": resp.provider,
                    "model": resp.model,
                    "response_id": response_id,
                }
            ],
            prompt=session.prompt + await evidence_context(db, session.file_ids, current_user_id),
            temperature=session.temperature,
            max_tokens=session.max_tokens,
            router=request.app.state.orchestrator.ceo.router,
            agent_type="playground",
        )
    )

    return APIResponse(
        data={"response_id": response_id, "status": "regenerating"},
        message="Response regeneration started",
    )


# ─── Export ──────────────────────────────────────────────────────────────


@router.get("/{session_id}/export")
async def export_session(
    session_id: str,
    format: str = "markdown",
    db: AsyncSession = Depends(get_db),
):
    from fastapi.responses import Response

    session = await _get_session_or_404(db, session_id)

    from app.models.playground_response import PlaygroundResponse

    resp_result = await db.execute(
        select(PlaygroundResponse).where(PlaygroundResponse.session_id == session_id)
    )
    responses = list(resp_result.scalars().all())

    if format == "json":
        payload = {
            "name": session.name,
            "prompt": session.prompt,
            "models": session.model_configs,
            "status": session.status,
            "responses": [
                {
                    "provider": r.provider,
                    "model": r.model,
                    "status": r.status,
                    "content": r.content,
                    "error": r.error,
                    "latency_ms": r.latency_ms,
                    "tokens_prompt": r.tokens_prompt,
                    "tokens_completion": r.tokens_completion,
                    "estimated_cost_usd": r.estimated_cost_usd,
                }
                for r in responses
            ],
        }
        return Response(
            content=json.dumps(payload, indent=2, default=str),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{session.name}.json"'
            },
        )

    if format == "markdown":
        content = f"# {session.name}\n\n"
        content += f"**Prompt:** {session.prompt}\n\n"
        models_str = ", ".join(
            f'{c["provider"]}:{c["model"]}' for c in session.model_configs
        )
        content += f"**Models:** {models_str}\n\n"
        content += f"**Settings:** Temperature={session.temperature}, Max Tokens={session.max_tokens}\n\n"
        content += "---\n\n"

        for r in responses:
            content += f"## {r.provider}:{r.model}\n\n"
            content += f"{r.content}\n\n"
            if r.tokens_prompt or r.tokens_completion:
                content += f"*Tokens: {r.tokens_prompt or 0} in / {r.tokens_completion or 0} out"
                if r.estimated_cost_usd:
                    content += f" \u2022 Cost: ${r.estimated_cost_usd:.6f}"
                content += "*\n\n"
            content += "---\n\n"

        return Response(
            content=content,
            media_type="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="{session.name}.md"'
            },
        )
    else:
        content = f"{session.name}\n{'=' * len(session.name)}\n\n"
        content += f"Prompt: {session.prompt}\n\n"
        for r in responses:
            content += f"\n{r.provider}:{r.model}\n{'-' * 40}\n"
            content += f"{r.content}\n\n"

        return Response(
            content=content,
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="{session.name}.txt"'
            },
        )
