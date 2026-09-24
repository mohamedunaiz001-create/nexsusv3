"""
Authentication scaffold: password hashing + JWT access/refresh tokens.
Credential encryption: AES-256-GCM for API keys stored in ProviderCredential.secret_ref

Phase 1 provides the framework only. Endpoints are wired but real user
lookup / OAuth flows are implemented in a later phase.
"""

import base64
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# =============================================================================
# AES-256-GCM Encryption for Provider Credentials
# =============================================================================


def _get_encryption_key() -> bytes:
    """
    Get the 32-byte encryption key from settings.
    Key must be a base64-encoded 32-byte (256-bit) value.
    """
    key_b64 = settings.ENCRYPTION_KEY
    if not key_b64:
        raise ValueError(
            'ENCRYPTION_KEY not configured. Generate with: python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"'
        )

    try:
        key = base64.b64decode(key_b64)
    except Exception as e:
        raise ValueError(
            f"Invalid ENCRYPTION_KEY (must be base64-encoded 32 bytes): {e}"
        )

    if len(key) != 32:
        raise ValueError(
            f"ENCRYPTION_KEY must be 32 bytes (256 bits), got {len(key)} bytes"
        )

    return key


def encrypt_secret(plaintext: str) -> str:
    """
    Encrypt a secret using AES-256-GCM.

    Returns a base64-encoded string containing: nonce (12 bytes) + ciphertext + tag (16 bytes)
    Format: base64(nonce + ciphertext + tag)

    The nonce is randomly generated for each encryption operation.
    """
    if not plaintext:
        raise ValueError("Cannot encrypt empty secret")

    key = _get_encryption_key()
    aesgcm = AESGCM(key)

    # Generate a random 12-byte nonce (recommended for GCM)
    nonce = os.urandom(12)

    # Encrypt - returns ciphertext + tag combined
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    # Combine nonce + ciphertext + tag
    encrypted_data = nonce + ciphertext_with_tag

    return base64.b64encode(encrypted_data).decode("utf-8")


def decrypt_secret(encrypted_b64: str) -> str:
    """
    Decrypt a secret that was encrypted with encrypt_secret().

    Expects base64-encoded string containing: nonce (12 bytes) + ciphertext + tag (16 bytes)
    """
    if not encrypted_b64:
        raise ValueError("Cannot decrypt empty value")

    key = _get_encryption_key()
    aesgcm = AESGCM(key)

    try:
        encrypted_data = base64.b64decode(encrypted_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding: {e}")

    if len(encrypted_data) < 12 + 16:  # nonce (12) + tag (16) minimum
        raise ValueError("Encrypted data too short")

    # Extract nonce (first 12 bytes) and ciphertext+tag (rest)
    nonce = encrypted_data[:12]
    ciphertext_with_tag = encrypted_data[12:]

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception as e:
        raise ValueError(f"Decryption failed (invalid key or corrupted data): {e}")

    return plaintext.decode("utf-8")


def generate_encryption_key() -> str:
    """
    Generate a new 32-byte base64-encoded encryption key.
    Use this to create ENCRYPTION_KEY for .env file.
    """
    return base64.b64encode(os.urandom(32)).decode("utf-8")


def create_token(
    subject: str, expires_delta: timedelta, token_type: str = "access"
) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


def create_access_token(subject: str) -> str:
    return create_token(
        subject,
        timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
        "access",
    )


def create_refresh_token(subject: str) -> str:
    return create_token(
        subject,
        timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
        "refresh",
    )


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
    except JWTError:
        return None


# =============================================================================
# Current-user resolution (Phase 5: file-ownership enforcement)
# =============================================================================
#
# Full RBAC/auth-required-on-every-route is still out of scope (see
# app/api/v1/endpoints/users.py), but Phase 5's file-security requirement —
# "one user cannot use another user's file ID" — needs *some* notion of
# "who is making this request" wherever evidence files are attached
# (upload, playground run, battle run). This is deliberately optional/
# best-effort: if no bearer token is sent, the caller is anonymous (None),
# matching migration 0004_phase5_evidence_user_optional's model, and can
# only touch anonymous (uploader_id IS NULL) evidence. It never 401s by
# itself — only the ownership check downstream does, and only when a
# file's owner doesn't match.

from fastapi import Header  # noqa: E402


async def get_current_user_id_optional(
    authorization: str | None = Header(default=None),
) -> Optional[str]:
    """Returns the JWT subject (user id) if a valid bearer token was sent,
    otherwise None. Never raises — an invalid/missing token just means the
    caller is treated as anonymous."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        return None
    return payload.get("sub")
