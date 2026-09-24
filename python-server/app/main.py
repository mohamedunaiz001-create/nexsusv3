"""
Port of server.ts

FastAPI application assembly: security headers (helmet equivalent), CORS,
cookie handling, per-route-group rate limiting, request logging, the API
router, and static-file serving of the built React frontend in production.
"""
from __future__ import annotations

import os
import socket
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.routes import router as api_router
from app.security import safe_logger, send_secure_error

PORT = int(os.environ.get("PORT", "8000"))
IS_PRODUCTION = os.environ.get("NODE_ENV") == "production"


def _validate_production_env() -> None:
    if not IS_PRODUCTION:
        return
    required = ["JWT_SECRET", "CSRF_SECRET", "ALLOWED_ORIGINS", "TOOL_ENCRYPTION_KEY"]
    missing = [name for name in required if not (os.environ.get(name) or "").strip()]
    if missing:
        raise RuntimeError(f"Missing required production environment variables: {', '.join(missing)}")
    if len(os.environ.get("JWT_SECRET", "")) < 64 or len(os.environ.get("CSRF_SECRET", "")) < 64:
        raise RuntimeError("JWT_SECRET and CSRF_SECRET must each be at least 64 characters in production.")
    import re
    if not re.fullmatch(r"[0-9a-fA-F]{64}", os.environ.get("TOOL_ENCRYPTION_KEY", "")):
        raise RuntimeError("TOOL_ENCRYPTION_KEY must be a 64-character hex string (32 bytes) in production. Generate with: openssl rand -hex 32")


_validate_production_env()

app = FastAPI(title="NEXSUS SOC API", redirect_slashes=False)


# ---------------------------------------------------------------------------
# Security headers (helmet equivalent)
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    csp = (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: blob: https:; connect-src 'self'; "
        "frame-ancestors 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
        + ("; upgrade-insecure-requests" if IS_PRODUCTION else "")
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


# ---------------------------------------------------------------------------
# CORS — mirrors the dynamic-origin allowlist check in server.ts
# ---------------------------------------------------------------------------
_allowed_origins = [o.strip() for o in (os.environ.get("ALLOWED_ORIGINS") or "").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins if IS_PRODUCTION else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token", "X-Requested-With"],
)


# ---------------------------------------------------------------------------
# Rate limiting — simple in-memory fixed-window limiter per client IP + bucket
# ---------------------------------------------------------------------------
class _RateLimiter:
    def __init__(self, window_s: float, max_requests: int, message: str, code: str):
        self.window_s = window_s
        self.max_requests = max_requests
        self.message = message
        self.code = code
        self._buckets: dict[str, dict] = {}

    def check(self, key: str) -> JSONResponse | None:
        now = time.monotonic()
        bucket = self._buckets.get(key)
        if not bucket or now - bucket["windowStart"] > self.window_s:
            self._buckets[key] = {"count": 1, "windowStart": now}
            return None
        if bucket["count"] >= self.max_requests:
            return JSONResponse(status_code=429, content={"success": False, "error": self.message, "code": self.code})
        bucket["count"] += 1
        return None


_global_limiter = _RateLimiter(60, 200, "Too many requests. Please slow down.", "RATE_LIMIT_EXCEEDED")
_ai_limiter = _RateLimiter(60, 30, "AI request limit reached (max 30/min).", "AI_RATE_LIMIT_EXCEEDED")
_auth_limiter = _RateLimiter(60, 20, "Too many authentication attempts.", "AUTH_RATE_LIMIT_EXCEEDED")
_tool_execute_limiter = _RateLimiter(60, 40, "Tool execution limit reached (max 40/min).", "TOOL_RATE_LIMIT_EXCEEDED")
_malware_intel_limiter = _RateLimiter(60, 20, "Malware intelligence intake limit reached (max 20/min).", "MALWARE_INTEL_RATE_LIMIT_EXCEEDED")


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/"):
        client_ip = request.client.host if request.client else "unknown"
        limited = _global_limiter.check(client_ip)
        if limited:
            return limited
        if path.startswith("/api/ai/"):
            limited = _ai_limiter.check(client_ip)
            if limited:
                return limited
        if path in ("/api/auth/login", "/api/auth/bootstrap"):
            limited = _auth_limiter.check(client_ip)
            if limited:
                return limited
        if path == "/api/tools/execute":
            limited = _tool_execute_limiter.check(client_ip)
            if limited:
                return limited
        if path.startswith("/api/malware-intel/") and ("upload" in path or path.endswith("/train")):
            limited = _malware_intel_limiter.check(client_ip)
            if limited:
                return limited
    return await call_next(request)


# ---------------------------------------------------------------------------
# Request logging
# ---------------------------------------------------------------------------
@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = int((time.monotonic() - start) * 1000)
        safe_logger.info(
            f"{request.method} {request.url.path} [{response.status_code}] - {duration_ms}ms",
            {"ip": request.client.host if request.client else None, "userAgent": request.headers.get("user-agent")},
        )
        return response
    return await call_next(request)


# ---------------------------------------------------------------------------
# Secure error rendering for raised HTTPExceptions (auth/CSRF dependencies)
# ---------------------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict) and "message" in exc.detail and "code" in exc.detail:
        return send_secure_error(exc.status_code, exc.detail["message"], exc.detail["code"])
    return send_secure_error(exc.status_code, str(exc.detail), "HTTP_ERROR")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Mirrors the zod `safeParse` failure path — a generic 400 without leaking field-level internals."""
    return send_secure_error(400, "Invalid request payload.", "VALIDATION_ERROR")


app.include_router(api_router, prefix="/api")


# ---------------------------------------------------------------------------
# Static frontend serving (production). In development, run the Vite dev
# server separately (see README_PYTHON.md) — FastAPI here only serves /api.
# ---------------------------------------------------------------------------
_dist_path = Path.cwd() / "dist"
if IS_PRODUCTION and _dist_path.exists():
    app.mount("/assets", StaticFiles(directory=str(_dist_path / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def spa_catch_all(full_path: str):
        index_file = _dist_path / "index.html"
        return FileResponse(str(index_file))


@app.on_event("startup")
async def on_startup() -> None:
    local_url = f"http://localhost:{PORT}"
    addresses = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if ":" not in addr and not addr.startswith("127."):
                addresses.append(f"http://{addr}:{PORT}")
    except Exception:  # noqa: BLE001
        pass
    print(f"\nNEXSUS SOC server is running.\n  Local:   {local_url}")
    for address in set(addresses):
        print(f"  Network: {address}")
    print("")
