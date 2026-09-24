"""
Playground Session ORM model.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any

from sqlalchemy import DateTime, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class PlaygroundSession(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A playground session with a prompt and multiple model configurations."""

    __tablename__ = "playground_sessions"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    model_configs: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=False)
    temperature: Mapped[float] = mapped_column(default=0.7)
    max_tokens: Mapped[int] = mapped_column(default=2000)
    file_ids: Mapped[List[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(
        String(20), default="created"
    )  # created, running, completed, partial, failed, stopped, error
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
