from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ProviderHealth(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Most recent reachability probe (ProviderClient.test_connection())
    result for a provider. One row per provider (keyed by the same
    machine name the live ProviderRouter uses — "openai", "anthropic",
    etc.), upserted on each check rather than a full time series.
    """

    __tablename__ = "provider_health"

    provider: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(
        String(20), default="unknown"
    )  # ok | error | unknown
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
