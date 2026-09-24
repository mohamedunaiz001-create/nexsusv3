from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Provider(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An AI model provider, e.g. OpenAI, Anthropic, Ollama."""

    __tablename__ = "providers"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    provider_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # cloud | local
    base_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
