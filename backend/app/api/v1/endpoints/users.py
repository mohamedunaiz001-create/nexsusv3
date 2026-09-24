from fastapi import APIRouter

from app.schemas.common import APIResponse

router = APIRouter()


@router.get("/me", response_model=APIResponse)
async def get_current_user_placeholder():
    # TODO(phase-2): resolve from JWT via a get_current_user dependency.
    return APIResponse(data=None, message="Not yet implemented")
