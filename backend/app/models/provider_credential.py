from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.security import decrypt_secret, encrypt_secret
from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ProviderCredential(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A credential record attached to a provider (by machine name, e.g.
    "openai" — the same key the live ProviderRouter uses).

    The raw secret is NEVER stored here — only an AES-256-GCM encrypted
    reference to where it lives (an env var name, or a secrets-manager key)
    plus a masked preview for display. This lets /settings/providers show
    "configured, key ending in ...ab12" without the API ever being able
    to leak a key.
    """

    __tablename__ = "provider_credentials"

    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    _secret_ref: Mapped[str] = mapped_column(
        "secret_ref", String(512), nullable=False
    )  # Stores base64(nonce + ciphertext + tag)
    masked_preview: Mapped[str | None] = mapped_column(String(20), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    @property
    def secret_ref(self) -> str:
        """Get the decrypted secret reference. NEVER expose this to frontend."""
        return decrypt_secret(self._secret_ref)

    @secret_ref.setter
    def secret_ref(self, value: str) -> None:
        """Set the encrypted secret reference."""
        if not value:
            raise ValueError("secret_ref cannot be empty")
        self._secret_ref = encrypt_secret(value)
        # Auto-generate masked preview from the plaintext (last 4 chars)
        self.masked_preview = f"••••{value[-4:]}" if len(value) >= 4 else "••••"

    def get_masked_preview(self) -> str:
        """
        Get masked preview safe for frontend display.
        This is the ONLY credential info that should ever be sent to the frontend.
        """
        return self.masked_preview or "••••"
