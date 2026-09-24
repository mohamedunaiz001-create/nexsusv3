"""Aggregates every endpoint router under /api/v1."""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    agents,
    audit_logs,
    auth,
    battle,
    cases,
    ceo_profiles,
    conversations,
    files,
    health,
    model_routing,
    models,
    orchestrate,
    playground,
    providers,
    reports,
    users,
)

api_router = APIRouter()

api_router.include_router(health.router, tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(providers.router, prefix="/providers", tags=["providers"])
api_router.include_router(models.router, prefix="/models", tags=["models"])
api_router.include_router(agents.router, prefix="/agents", tags=["agents"])
api_router.include_router(
    model_routing.router, prefix="/model-routing", tags=["model-routing"]
)
api_router.include_router(ceo_profiles.router, prefix="/ceo-profiles", tags=["ceo"])
api_router.include_router(
    orchestrate.router, prefix="/orchestrate", tags=["orchestration"]
)
api_router.include_router(
    conversations.router, prefix="/conversations", tags=["conversations"]
)
api_router.include_router(cases.router, prefix="/cases", tags=["cases"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(files.router, prefix="/files", tags=["files"])
api_router.include_router(audit_logs.router, prefix="/audit-logs", tags=["audit-logs"])
api_router.include_router(playground.router, prefix="/playground", tags=["playground"])
api_router.include_router(battle.router, prefix="/battle", tags=["battle"])
