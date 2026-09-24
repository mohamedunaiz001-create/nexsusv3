"""
Port of server/auth.ts

JWT session issuance/verification, PBKDF2 password hashing with
timing-safe comparison, HMAC-signed CSRF tokens, and FastAPI
dependencies for authentication / RBAC / CSRF enforcement.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Cookie, Header, HTTPException, Request

from app.database import create_session, is_session_active
from app.database import revoke_session as _revoke_stored_session
from app.database import revoke_all_user_sessions as _revoke_stored_user_sessions
from app.security import safe_logger

IS_PRODUCTION = os.environ.get("NODE_ENV") == "production"


def _require_secret(name: str) -> str:
    value = (os.environ.get(name) or "").strip()
    if value and len(value) >= 64:
        return value
    if IS_PRODUCTION:
        raise RuntimeError(f"{name} environment variable is required and must be at least 64 characters in production.")
    generated = secrets.token_hex(64)
    safe_logger.warn(f"{name} not configured; generated ephemeral development secret. Set {name} for stable local sessions.")
    return generated


JWT_SECRET = _require_secret("JWT_SECRET")
CSRF_SECRET = _require_secret("CSRF_SECRET")


@dataclass
class UserPayload:
    id: str
    name: str
    email: str
    role: str  # 'Admin' | 'Analyst' | 'Viewer' | 'Agent'
    badge: str
    clearance: str  # 'TOP_SECRET' | 'SECRET' | 'CONFIDENTIAL' | 'RESTRICTED'

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "email": self.email, "role": self.role, "badge": self.badge, "clearance": self.clearance}


@dataclass
class StoredAccount:
    user: UserPayload
    salt: str
    password_hash: str


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), bytes.fromhex(salt), 100000, dklen=64).hex()


def _resolve_initial_password(env_value: Optional[str], env_var_name: str) -> Optional[str]:
    if env_value and len(env_value.strip()) >= 12:
        return env_value
    if env_value and len(env_value.strip()) > 0:
        safe_logger.warn(f"{env_var_name} is set but shorter than the required 12 characters — ignoring it.")
    if IS_PRODUCTION:
        return None
    generated = secrets.token_urlsafe(18)
    print(f"\n[DEV ONLY] {env_var_name} is not set. Generated a temporary local login password:\n  {generated}\nSet {env_var_name} in your environment for a stable password across restarts.\n")
    return generated


_SALT_ADMIN = secrets.token_hex(16)
_SALT_ANALYST = secrets.token_hex(16)
_SALT_VIEWER = secrets.token_hex(16)
_PASS_ADMIN = _resolve_initial_password(os.environ.get("ADMIN_INITIAL_PASSWORD"), "ADMIN_INITIAL_PASSWORD")
_PASS_ANALYST = _resolve_initial_password(os.environ.get("ANALYST_INITIAL_PASSWORD"), "ANALYST_INITIAL_PASSWORD")
_PASS_VIEWER = _resolve_initial_password(os.environ.get("VIEWER_INITIAL_PASSWORD"), "VIEWER_INITIAL_PASSWORD")


def _build_account(password: Optional[str], salt: str, user: UserPayload) -> Optional[StoredAccount]:
    if not password:
        safe_logger.warn(f"Account '{user.email}' left unprovisioned — no password configured for production.", {"role": user.role})
        return None
    return StoredAccount(user=user, salt=salt, password_hash=_hash_password(password, salt))


_candidate_accounts = [
    _build_account(_PASS_ADMIN, _SALT_ADMIN, UserPayload(id="usr-admin-01", name="Commander Marcus Vance", email="m.vance@nexsus-soc.mil", role="Admin", badge="CHIEF OF SOC", clearance="TOP_SECRET")),
    _build_account(_PASS_ANALYST, _SALT_ANALYST, UserPayload(id="usr-analyst-02", name="Specialist Elena Rostova", email="e.rostova@nexsus-soc.mil", role="Analyst", badge="SENIOR IR ANALYST", clearance="SECRET")),
    _build_account(_PASS_VIEWER, _SALT_VIEWER, UserPayload(id="usr-viewer-03", name="Auditor David Chen", email="d.chen@compliance-audit.org", role="Viewer", badge="COMPLIANCE AUDITOR", clearance="CONFIDENTIAL")),
]
AUTHORIZED_ACCOUNTS: dict[str, StoredAccount] = {a.user.email: a for a in _candidate_accounts if a is not None}


def self_test_admin_auth() -> dict:
    if not _PASS_ADMIN:
        return {"adminLoginWorks": False, "wrongPasswordRejected": True, "unknownUserRejected": True}
    admin_user = verify_user_credentials("m.vance@nexsus-soc.mil", _PASS_ADMIN)
    bad_pass = verify_user_credentials("m.vance@nexsus-soc.mil", "WrongPassword!123")
    unknown_user = verify_user_credentials("nonexistent@domain.com", "SomePassword!123")
    return {
        "adminLoginWorks": bool(admin_user) and admin_user.role == "Admin",
        "wrongPasswordRejected": bad_pass is None,
        "unknownUserRejected": unknown_user is None,
    }


def verify_user_credentials(email: str, password_attempt: str) -> Optional[UserPayload]:
    account = AUTHORIZED_ACCOUNTS.get(email.lower().strip())
    if not account:
        # Still perform a hash + timing-safe comparison so response time doesn't
        # leak whether the account exists.
        dummy_salt = "00" * 16
        a = _hash_password("dummy_pass", dummy_salt)
        b = _hash_password(password_attempt, dummy_salt)
        hmac.compare_digest(bytes.fromhex(a), bytes.fromhex(b))
        return None
    attempt = bytes.fromhex(_hash_password(password_attempt, account.salt))
    expected = bytes.fromhex(account.password_hash)
    if len(attempt) != len(expected):
        return None
    return account.user if hmac.compare_digest(expected, attempt) else None


def generate_auth_token(user: UserPayload) -> str:
    session_id = str(uuid.uuid4())
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat().replace("+00:00", "Z")
    create_session(session_id, user.id, expires_at)
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.id, "name": user.name, "email": user.email, "role": user.role,
        "badge": user.badge, "clearance": user.clearance, "jti": session_id,
        "iat": now, "exp": now + timedelta(hours=8),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def revoke_session(session_id: str) -> None:
    if session_id:
        _revoke_stored_session(session_id)


def revoke_all_user_sessions(user_id: str) -> None:
    if user_id:
        _revoke_stored_user_sessions(user_id)


def generate_csrf_token() -> str:
    random_value = secrets.token_hex(32)
    timestamp = str(int(datetime.now(timezone.utc).timestamp() * 1000))
    signature = hmac.new(CSRF_SECRET.encode("utf-8"), f"{random_value}:{timestamp}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{random_value}.{timestamp}.{signature}"


def validate_csrf_token(token: Optional[str]) -> bool:
    if not token or not isinstance(token, str):
        return False
    parts = token.split(".")
    if len(parts) != 3:
        return False
    random_value, timestamp, signature = parts
    try:
        time_num = int(timestamp)
    except ValueError:
        return False
    age = int(datetime.now(timezone.utc).timestamp() * 1000) - time_num
    if age < 0 or age > 8 * 3600 * 1000:
        return False
    import re
    if not re.fullmatch(r"[a-f0-9]{64}", random_value, re.IGNORECASE) or not re.fullmatch(r"[a-f0-9]{64}", signature, re.IGNORECASE):
        return False
    expected = hmac.new(CSRF_SECRET.encode("utf-8"), f"{random_value}:{timestamp}".encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

class AuthContext:
    """Equivalent of the mutated Express request (`req.user`, `req.sessionId`)."""

    def __init__(self, user: UserPayload, session_id: str):
        self.user = user
        self.session_id = session_id


async def authenticate_token(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    nexsus_session: Optional[str] = Cookie(default=None),
) -> AuthContext:
    token: Optional[str] = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    if not token:
        token = nexsus_session
    if not token:
        raise _secure_http_exception(401, "Authentication required. No valid session or authorization token provided.", "AUTH_REQUIRED")
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if not decoded.get("sub") or not decoded.get("role") or not decoded.get("jti"):
            raise _secure_http_exception(401, "Invalid session payload structure.", "INVALID_TOKEN_PAYLOAD")
        if not is_session_active(decoded["jti"]):
            raise _secure_http_exception(401, "Session is expired or has been revoked. Please log in again.", "SESSION_INVALID")
        user = UserPayload(
            id=decoded["sub"], name=decoded.get("name") or "Unknown Operator", email=decoded.get("email") or "",
            role=decoded["role"], badge=decoded.get("badge") or "SOC OPERATOR", clearance=decoded.get("clearance") or "CONFIDENTIAL",
        )
        request.state.user = user
        request.state.session_id = decoded["jti"]
        return AuthContext(user=user, session_id=decoded["jti"])
    except jwt.ExpiredSignatureError:
        safe_logger.warn("JWT verification failed", {"error": "TokenExpiredError"})
        raise _secure_http_exception(401, "Session token has expired. Please log in again.", "TOKEN_EXPIRED")
    except HTTPException:
        raise
    except Exception as err:  # jwt.InvalidTokenError and friends
        safe_logger.warn("JWT verification failed", {"error": str(err)})
        raise _secure_http_exception(401, "Invalid session token signature.", "TOKEN_INVALID")


def _secure_http_exception(status_code: int, message: str, code: str) -> HTTPException:
    """Raises an HTTPException carrying the secure-error payload as its detail, rendered by an exception handler."""
    return HTTPException(status_code=status_code, detail={"message": message, "code": code})


def require_role(allowed_roles: list[str]):
    """Dependency factory: `Depends(require_role(['Admin','Analyst']))`. Chains after `authenticate_token`."""
    from fastapi import Depends

    async def _checker(auth: AuthContext = Depends(authenticate_token)) -> AuthContext:
        if auth.user.role not in allowed_roles:
            safe_logger.warn("Access denied: insufficient privileges", {"userId": auth.user.id, "userRole": auth.user.role, "requiredRoles": allowed_roles})
            raise _secure_http_exception(403, f"Access denied. Role '{auth.user.role}' lacks required permissions.", "FORBIDDEN_ROLE")
        return auth

    return _checker


async def verify_csrf(
    request: Request,
    x_csrf_token: Optional[str] = Header(default=None),
    nexsus_csrf: Optional[str] = Cookie(default=None),
) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    exempt_paths = {"/api/auth/login", "/api/auth/csrf-token", "/api/auth/bootstrap"}
    if request.url.path in exempt_paths:
        return
    if not x_csrf_token or not nexsus_csrf or x_csrf_token != nexsus_csrf or not validate_csrf_token(x_csrf_token):
        raise _secure_http_exception(403, "CSRF token validation failed. State-changing requests require a matching valid X-CSRF-Token header and CSRF cookie.", "CSRF_INVALID")
