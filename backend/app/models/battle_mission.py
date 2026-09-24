"""
Battle Mission ORM model - pre-built cybersecurity missions.
"""

from typing import Dict

from sqlalchemy import Boolean, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class BattleMission(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Pre-built cybersecurity battle missions."""

    __tablename__ = "battle_missions"

    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    mission_type: Mapped[str] = mapped_column(String(50), nullable=False)
    system_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    scoring_weights: Mapped[Dict[str, float]] = mapped_column(JSON, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
