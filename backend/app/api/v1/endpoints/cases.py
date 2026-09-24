"""
Cases endpoints — Phase 1 placeholder routes.

Wired into the router and OpenAPI docs now so the frontend and future
phases have a stable contract to build against.
"""

from fastapi import APIRouter

from app.schemas.common import APIResponse

router = APIRouter()


@router.get("", response_model=APIResponse)
async def list_cases():
    return APIResponse(data=[], message="Cases listing placeholder")
