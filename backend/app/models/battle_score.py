"""
Battle Score ORM model - stores AI Judge scoring results.
"""

import uuid
from typing import Optional

from sqlalchemy import Float, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class BattleScore(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """AI Judge scoring for a model in a battle."""

    __tablename__ = "battle_scores"

    battle_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("battle_sessions.id"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(150), nullable=False)
    accuracy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    depth: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    actionability: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    evidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    speed: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    total_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # Cybersecurity-specific scores
    ioc_precision: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ioc_recall: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    mitre_accuracy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    detection_accuracy: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    recommendation_quality: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )
    judge_reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
