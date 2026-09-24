"""
Wires the framework-agnostic `agents/` package into this FastAPI app.

Holds the single live Orchestrator instance on `app.state`. When a user
switches the active CEO profile via /api/v1/ceo-profiles, we rebuild the
CEO (and its planner) in place without dropping the registered specialist
agents, provider router, or event history.
"""

import sys
from pathlib import Path

# `agents/` lives at the repo root, one level above apps/api.
REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.bootstrap import CEOConfig, ProviderConfig, build_orchestrator  # noqa: E402
from agents.ceo.hermes_ceo import HermesCEOAgent  # noqa: E402
from agents.ceo.planner import CEOPlanner  # noqa: E402
from agents.orchestration.orchestrator import Orchestrator  # noqa: E402
from agents.providers.provider_router import ModelRequest, ModelResponse  # noqa: E402
from agents.providers.router_impl import RoutingAttempt  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.logging import get_logger  # noqa: E402

logger = get_logger(__name__)


def create_orchestrator() -> Orchestrator:
    # NOTE: previously only openai/anthropic/ollama keys were forwarded here
    # even though ProviderConfig (and settings) already had Gemini/Groq —
    # meaning those two providers could never actually be "configured" via
    # the running app. Fixed as part of the Phase 4 Provider Hub work.
    provider_config = ProviderConfig(
        openai_api_key=settings.OPENAI_API_KEY,
        anthropic_api_key=settings.ANTHROPIC_API_KEY,
        gemini_api_key=settings.GEMINI_API_KEY,
        groq_api_key=settings.GROQ_API_KEY,
        ollama_base_url=settings.OLLAMA_BASE_URL,
    )
    orchestrator = build_orchestrator(
        provider_config=provider_config, ceo_config=CEOConfig()
    )
    _wire_usage_and_decision_hooks(orchestrator)
    return orchestrator


def _wire_usage_and_decision_hooks(orchestrator: Orchestrator) -> None:
    """
    Attaches Phase 4 usage/decision tracking to the live ProviderRouter.

    Kept here (API layer) rather than in agents/ so the agents/ package
    stays database-agnostic (see bootstrap.py's module docstring) — the
    router only knows about a generic async callback, not about
    SQLAlchemy or ModelUsage/RoutingDecision specifically.
    """
    from app.db.session import AsyncSessionLocal  # local import: avoids a
    from app.models.model_usage import ModelUsage  # circular import between
    from app.models.routing_decision import RoutingDecision  # db/session and core

    router = orchestrator.ceo.router

    async def on_usage(
        request: ModelRequest, response: ModelResponse, latency_ms: float
    ):
        usage = response.usage or {}
        try:
            async with AsyncSessionLocal() as session:
                # Calculate estimated cost if pricing is available
                from agents.providers.model_registry import calculate_estimated_cost

                estimated_cost = calculate_estimated_cost(
                    provider=response.provider,
                    model=response.model,
                    prompt_tokens=usage.get("prompt_tokens"),
                    completion_tokens=usage.get("completion_tokens"),
                )

                session.add(
                    ModelUsage(
                        provider=response.provider,
                        model=response.model,
                        prompt_tokens=usage.get("prompt_tokens"),
                        completion_tokens=usage.get("completion_tokens"),
                        latency_ms=latency_ms,
                        estimated_cost_usd=estimated_cost,
                    )
                )
                await session.commit()
        except Exception as exc:  # noqa: BLE001 - never let logging break a request
            logger.error("usage_tracking_failed", error=str(exc))

    async def on_decision(attempt: RoutingAttempt):
        try:
            async with AsyncSessionLocal() as session:
                session.add(
                    RoutingDecision(
                        provider=attempt.provider,
                        model=attempt.model,
                        succeeded=attempt.succeeded,
                        error_kind=attempt.error_kind,
                        error_message=attempt.error_message,
                        latency_ms=attempt.latency_ms,
                    )
                )
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            logger.error("routing_decision_log_failed", error=str(exc))

    router.set_usage_hook(on_usage)
    router.set_decision_hook(on_decision)


def apply_ceo_profile(orchestrator: Orchestrator, profile) -> None:
    """Rebuild the CEO (and its planner) from a CEOProfile ORM row, in place."""
    planner = CEOPlanner(
        orchestrator.ceo.router, provider=profile.provider, model=profile.model
    )
    orchestrator.ceo = HermesCEOAgent(
        agent_manager=orchestrator.ceo.agent_manager,
        provider_router=orchestrator.ceo.router,
        planner=planner,
        provider=profile.provider,
        model=profile.model,
        temperature=profile.temperature,
        system_prompt=profile.system_prompt,
        memory_service=orchestrator.ceo.memory,
        memory_enabled=profile.memory_enabled,
    )
