"""
Port of server/tools/crypto.ts

Encrypts/decrypts vendor API keys at rest using AES-256-GCM.
"""
from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.security import safe_logger

_IS_PRODUCTION = os.environ.get("NODE_ENV") == "production"


def _resolve_encryption_key() -> bytes:
    raw = (os.environ.get("TOOL_ENCRYPTION_KEY") or "").strip()
    if raw and re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        return bytes.fromhex(raw)
    if raw:
        if _IS_PRODUCTION:
            raise RuntimeError("TOOL_ENCRYPTION_KEY must be a 64-character hex string (32 bytes) in production.")
        safe_logger.warn("TOOL_ENCRYPTION_KEY is set but is not a valid 64-char hex string; ignoring it.")
    if _IS_PRODUCTION:
        raise RuntimeError("TOOL_ENCRYPTION_KEY environment variable is required in production (generate with: openssl rand -hex 32).")
    generated = secrets.token_bytes(32)
    safe_logger.warn("TOOL_ENCRYPTION_KEY not configured; generated an ephemeral development key. Connected tool credentials will not survive a server restart. Set TOOL_ENCRYPTION_KEY for stable storage.")
    return generated


_ENCRYPTION_KEY = _resolve_encryption_key()
_AESGCM = AESGCM(_ENCRYPTION_KEY)


@dataclass
class EncryptedPayload:
    ciphertext: str  # hex
    iv: str  # hex
    tag: str  # hex


def encrypt_secret(plaintext: str) -> EncryptedPayload:
    """Encrypts a secret (e.g. a vendor API key) for storage in the database. Never stored or logged in plaintext."""
    iv = secrets.token_bytes(12)
    combined = _AESGCM.encrypt(iv, plaintext.encode("utf-8"), None)
    # PyCA's AESGCM appends the 16-byte auth tag to the ciphertext; split it out
    # to mirror Node's separate ciphertext/tag fields.
    ciphertext, tag = combined[:-16], combined[-16:]
    return EncryptedPayload(ciphertext=ciphertext.hex(), iv=iv.hex(), tag=tag.hex())


def decrypt_secret(payload: EncryptedPayload) -> str:
    """Decrypts a stored credential. Only ever called server-side, immediately before an outbound adapter call."""
    combined = bytes.fromhex(payload.ciphertext) + bytes.fromhex(payload.tag)
    plaintext = _AESGCM.decrypt(bytes.fromhex(payload.iv), combined, None)
    return plaintext.decode("utf-8")
