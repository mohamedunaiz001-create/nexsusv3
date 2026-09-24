from sqlalchemy import Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ModelUsage(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    One row per completed provider call — the raw log that usage/cost
    analytics (GET /providers/usage) aggregates over. Written by
    DefaultProviderRouter's usage hook (see app.core.orchestration), so
    the agents/ package itself never touches the database directly.
    """

    __tablename__ = "model_usage"

    agent_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(150), nullable=False)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    estimated_cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
