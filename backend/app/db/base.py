"""
Declarative base + common mixins used by every ORM model.
Import every model module here so Alembic autogenerate can see them.
"""

import uuid
from datetime import datetime

from sqlalchemy import CHAR, DateTime, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    pass


class GUID(TypeDecorator):
    """Platform-independent UUID: native `UUID` on Postgres (production),
    `CHAR(32)` hex on everything else (e.g. sqlite, used by the test suite
    so endpoint tests don't require a running Postgres instance)."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(32))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            return str(value)
        return uuid.UUID(str(value)).hex

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, uuid.UUID):
            return uuid.UUID(value)
        return value


class UUIDPrimaryKeyMixin:
    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# Import models so Alembic can discover them via Base.metadata
from app.models import (  # noqa: E402,F401
    agent,
    agent_model_assignment,
    audit_log,
    battle_mission,
    battle_response,
    battle_score,
    battle_session,
    case,
    ceo_profile,
    conversation,
    file,
    model,
    model_usage,
    playground_response,
    playground_session,
    provider,
    provider_credential,
    provider_health,
    report,
    routing_decision,
    routing_policy,
    user,
)
