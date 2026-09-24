from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Agent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A registered AI agent (CEO/Hermes orchestrator or a specialist)."""

    __tablename__ = "agents"

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    agent_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # ceo | specialist
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    system_prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)
