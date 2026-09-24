from sqlalchemy import Boolean, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class CEOProfile(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A user-configurable CEO persona (Phase 2: "CEO Settings").

    Users can create/duplicate/delete profiles and choose which one is
    active — nothing about the orchestrator is hardcoded to "Hermes".
    """

    __tablename__ = "ceo_profiles"

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    system_prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False, default="ollama")
    model: Mapped[str] = mapped_column(String(150), nullable=False, default="llama3")
    temperature: Mapped[float] = mapped_column(Float, default=0.2)
    memory_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
