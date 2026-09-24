"""
CEO Settings endpoints (Phase 2 deliverable #12).

Users can create, delete, duplicate, and choose the active CEO profile,
assign its model/provider, edit its prompt, change temperature, and
enable memory. Activating a profile rebuilds the live orchestrator's CEO
in place (see app.core.orchestration.apply_ceo_profile).
"""

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.core.orchestration import apply_ceo_profile
from app.db.session import get_db
from app.models.ceo_profile import CEOProfile
from app.schemas.ceo_profile import CEOProfileCreate, CEOProfileRead, CEOProfileUpdate
from app.schemas.common import APIResponse

router = APIRouter()


async def _get_or_404(db: AsyncSession, profile_id: uuid.UUID) -> CEOProfile:
    profile = await db.get(CEOProfile, profile_id)
    if profile is None:
        raise NotFoundError(f"No CEO profile with id '{profile_id}'")
    return profile


@router.get("", response_model=APIResponse[list[CEOProfileRead]])
async def list_ceo_profiles(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CEOProfile))
    profiles = list(result.scalars().all())
    return APIResponse(
        data=[CEOProfileRead.model_validate(p) for p in profiles],
        message=f"{len(profiles)} profile(s)",
    )


@router.post("", response_model=APIResponse[CEOProfileRead])
async def create_ceo_profile(
    payload: CEOProfileCreate, db: AsyncSession = Depends(get_db)
):
    profile = CEOProfile(**payload.model_dump())
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    return APIResponse(
        data=CEOProfileRead.model_validate(profile), message="CEO profile created"
    )


@router.get("/{profile_id}", response_model=APIResponse[CEOProfileRead])
async def get_ceo_profile(profile_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    profile = await _get_or_404(db, profile_id)
    return APIResponse(data=CEOProfileRead.model_validate(profile), message="ok")


@router.patch("/{profile_id}", response_model=APIResponse[CEOProfileRead])
async def update_ceo_profile(
    profile_id: uuid.UUID, payload: CEOProfileUpdate, db: AsyncSession = Depends(get_db)
):
    profile = await _get_or_404(db, profile_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(profile, field, value)
    await db.commit()
    await db.refresh(profile)
    return APIResponse(
        data=CEOProfileRead.model_validate(profile), message="CEO profile updated"
    )


@router.delete("/{profile_id}", response_model=APIResponse[None])
async def delete_ceo_profile(profile_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    profile = await _get_or_404(db, profile_id)
    await db.delete(profile)
    await db.commit()
    return APIResponse(message="CEO profile deleted")


@router.post("/{profile_id}/duplicate", response_model=APIResponse[CEOProfileRead])
async def duplicate_ceo_profile(
    profile_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    original = await _get_or_404(db, profile_id)
    copy = CEOProfile(
        name=f"{original.name} (copy)",
        description=original.description,
        system_prompt=original.system_prompt,
        provider=original.provider,
        model=original.model,
        temperature=original.temperature,
        memory_enabled=original.memory_enabled,
        is_active=False,
    )
    db.add(copy)
    await db.commit()
    await db.refresh(copy)
    return APIResponse(
        data=CEOProfileRead.model_validate(copy), message="CEO profile duplicated"
    )


@router.post("/{profile_id}/activate", response_model=APIResponse[CEOProfileRead])
async def activate_ceo_profile(
    profile_id: uuid.UUID, request: Request, db: AsyncSession = Depends(get_db)
):
    profile = await _get_or_404(db, profile_id)

    result = await db.execute(select(CEOProfile).where(CEOProfile.is_active.is_(True)))
    for other in result.scalars().all():
        other.is_active = False
    profile.is_active = True
    await db.commit()
    await db.refresh(profile)

    apply_ceo_profile(request.app.state.orchestrator, profile)

    return APIResponse(
        data=CEOProfileRead.model_validate(profile), message="CEO profile activated"
    )
