"""
Models endpoints — Phase 4: real model discovery.

GET /models aggregates each configured provider's live list_models()
(so it reflects models actually pulled/available right now — especially
important for Ollama) merged with the static capability registry
(context window, tool/vision support, cost tier) so the frontend can
show and filter on real metadata instead of bare model-name strings.

Providers that are registered but not configured (missing API key) are
skipped for the live call but still reported so the UI can explain why
their models aren't listed.
"""

from fastapi import APIRouter, Request

from agents.providers.model_registry import get_model_capabilities
from app.schemas.common import APIResponse

router = APIRouter()


@router.get("", response_model=APIResponse[list[dict]])
async def list_models(request: Request):
    router_ = request.app.state.orchestrator.ceo.router
    configured = set(await router_.configured_providers())

    data: list[dict] = []
    unavailable: list[dict] = []

    for provider_name in router_.available_providers():
        if provider_name not in configured:
            unavailable.append({"provider": provider_name, "reason": "not configured"})
            continue

        client = router_.get_client(provider_name)
        try:
            models = await client.list_models()
        except (
            Exception
        ) as exc:  # noqa: BLE001 - one bad provider shouldn't 500 the whole list
            unavailable.append({"provider": provider_name, "reason": str(exc)})
            continue

        for m in models:
            model_id = m.get("id")
            if not model_id:
                continue
            caps = get_model_capabilities(provider_name, model_id)
            data.append({**caps, "id": model_id})

    return APIResponse(
        data=data,
        message=(
            f"{len(data)} model(s) across {len(configured)} configured provider(s)"
            + (f"; {len(unavailable)} provider(s) unavailable" if unavailable else "")
        ),
    )


@router.get("/registry", response_model=APIResponse[list[dict]])
async def list_known_models():
    """The static capability registry itself (agents/providers/model_registry.py)
    — useful for a routing-policy UI that wants to reason about models the
    account may not have pulled/enabled yet."""
    from agents.providers.model_registry import all_known_models

    known = all_known_models()
    return APIResponse(data=known, message=f"{len(known)} known model(s) in registry")


@router.get("/{provider}/{model}/capabilities", response_model=APIResponse[dict])
async def model_capabilities(provider: str, model: str):
    caps = get_model_capabilities(provider, model)
    return APIResponse(
        data=caps, message="ok" if caps["known"] else "unknown model — showing defaults"
    )
