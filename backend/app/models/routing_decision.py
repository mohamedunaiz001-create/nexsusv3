from sqlalchemy import Boolean, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RoutingDecision(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    One row per routing *hop* (not just the final winner) — lets
    /providers/routing-log show "tried openai:gpt-4o -> 429, fell back to
    anthropic:claude-sonnet-5 -> ok" instead of only the final result.
    Written by DefaultProviderRouter's decision hook.
    """

    __tablename__ = "routing_decisions"

    agent_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(150), nullable=False)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=False)
    error_kind: Mapped[str | None] = mapped_column(String(30), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
