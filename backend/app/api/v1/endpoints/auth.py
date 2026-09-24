"""
Authentication scaffold: register / login / refresh.

Phase 1 wires the JWT issuing flow against the users table. OAuth
(Google/GitHub) and RBAC enforcement land in a later phase — this module
only exposes the interfaces they'll plug into.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AppException
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from app.db.session import get_db
from app.models.user import User
from app.schemas.common import APIResponse
from app.schemas.user import Token, UserCreate, UserRead

router = APIRouter()


@router.post("/register", response_model=APIResponse[UserRead])
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.scalar(select(User).where(User.email == payload.email))
    if existing:
        raise AppException("Email already registered", status_code=409)

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return APIResponse(data=UserRead.model_validate(user), message="User registered")


@router.post("/login", response_model=APIResponse[Token])
async def login(email: str, password: str, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(User).where(User.email == email))
    if not user or not verify_password(password, user.hashed_password):
        raise AppException("Invalid credentials", status_code=401)

    token = Token(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
    )
    return APIResponse(data=token, message="Login successful")


@router.post("/oauth/{provider}")
async def oauth_login(provider: str):
    # TODO(phase-2): implement Google / GitHub OAuth code exchange.
    raise AppException(
        f"OAuth provider '{provider}' not yet implemented", status_code=501
    )
