"""
Playground Response ORM model.
"""

import uuid
from typing import Optional, Dict, Any

from sqlalchemy import Float, Integer, String, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class PlaygroundResponse(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A single model's response in a playground session."""

    __tablename__ = "playground_responses"

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("playground_sessions.id"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(150), nullable=False)
    content: Mapped[str] = mapped_column(Text, default="")
    structured: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    tokens_prompt: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    tokens_completion: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    estimated_cost_usd: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), default="streaming"
    )  # streaming, completed, error, stopped
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
