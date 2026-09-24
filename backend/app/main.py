"""
CyberResearch-X Enterprise (nexsus) — FastAPI application entrypoint.

Phase 1 scope: application skeleton, routing, config, logging, exception
handling, CORS/security headers, and OpenAPI docs. No cybersecurity
analysis features are implemented yet — see agents/ for the orchestration
interfaces that later phases will fill in.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.orchestration import create_orchestrator
from app.middleware.logging import RequestLoggingMiddleware
from app.middleware.rate_limit import RateLimitMiddleware

configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("startup", app_name=settings.APP_NAME, env=settings.APP_ENV)
    # Phase 2: build the CEO / AgentManager / ProviderRouter / EventBus once
    # and keep them alive for the life of the process.
    app.state.orchestrator = create_orchestrator()
    logger.info(
        "orchestrator_ready",
        agents=[
            a.agent_type for a in app.state.orchestrator.ceo.agent_manager.list_agents()
        ],
    )
    yield
    logger.info("shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        description="AI-powered cybersecurity research & operations platform.",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # ---- Security headers / CORS ----
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RateLimitMiddleware)

    register_exception_handlers(app)

    app.include_router(api_router, prefix=settings.API_V1_PREFIX)

    @app.get("/")
    async def root():
        return {"service": settings.APP_NAME, "status": "running", "docs": "/api/docs"}

    return app


app = create_app()
