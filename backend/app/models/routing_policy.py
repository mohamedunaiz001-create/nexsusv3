from sqlalchemy import JSON, Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class RoutingPolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A named, reusable routing rule set (e.g. "cost-optimized",
    "quality-first", "local-only-after-hours"). `rules` is a small JSON
    blob interpreted by the API layer when building an agent's
    ModelRequest fallback chain — kept schema-light on purpose since
    routing strategies are expected to evolve quickly during Phase 4.

    Example `rules`:
        {"strategy": "cost_optimized", "min_context_window": 32000,
         "excluded_providers": ["groq"]}
    """

    __tablename__ = "routing_policies"

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rules: Mapped[dict] = mapped_column(JSON, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
