from fastapi import APIRouter

from app.core.config import settings
from app.schemas.common import APIResponse, HealthStatus

router = APIRouter()


@router.get("/health", response_model=APIResponse[HealthStatus])
async def health_check():
    return APIResponse(
        data=HealthStatus(
            status="ok",
            app_name=settings.APP_NAME,
            app_env=settings.APP_ENV,
            version="0.1.0",
        ),
        message="Service is healthy",
    )
