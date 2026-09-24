import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AIModel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A specific model exposed by a provider, e.g. gpt-4o, llama3."""

    __tablename__ = "models"

    provider_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("providers.id")
    )
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    context_window: Mapped[int | None] = mapped_column(nullable=True)
    role: Mapped[str] = mapped_column(
        String(50), default="general"
    )  # ceo | specialist | general
