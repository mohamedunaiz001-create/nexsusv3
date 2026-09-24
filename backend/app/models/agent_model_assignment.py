from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AgentModelAssignment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    Which provider/model a given agent currently uses, plus an ordered
    fallback chain. This is what /settings/model-routing reads and
    writes — the Phase 4 milestone of "every agent gets its own model
    assignment" (see docs/PHASE4.md).

    Keyed by `agent_type` (e.g. "malware_analysis", "ceo") rather than a
    FK to the `agents` table: that's the same string key the live
    AgentManager registry already uses (see agents/manager/*, and
    GET /api/v1/agents/{agent_type}), so an assignment can be applied to
    the *running* agent immediately, not just persisted for later.
    """

    __tablename__ = "agent_model_assignments"

    agent_type: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(150), nullable=False)
    # Ordered fallback chain as "provider:model" strings, tried in order if
    # the primary fails. Kept as a simple string list rather than a join
    # table — the ordering *is* the data, and chains are short (2-4 hops).
    fallback_chain: Mapped[list[str]] = mapped_column(JSON, default=list)
    priority: Mapped[int] = mapped_column(Integer, default=0)
