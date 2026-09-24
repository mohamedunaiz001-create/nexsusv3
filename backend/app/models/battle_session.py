"""
Battle Session ORM model.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any

from sqlalchemy import DateTime, Float, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class BattleSession(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A battle session with multiple models competing on a cybersecurity mission."""

    __tablename__ = "battle_sessions"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    mission_type: Mapped[str] = mapped_column(String(50), nullable=False)
    task_description: Mapped[str] = mapped_column(Text, nullable=False)
    file_ids: Mapped[List[str]] = mapped_column(JSON, default=list)
    model_configs: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="created"
    )  # created, running, completed, partial, failed, stopped, error
    winner_model: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    winner_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    judge_reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
