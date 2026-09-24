"""
Rate-limiting hook (framework only).

Phase 1 wires the middleware and a pluggable backend interface (Redis-backed
in production). The actual limiter algorithm/thresholds are configured in a
later phase once real traffic patterns are known.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class RateLimitMiddleware(BaseHTTPMiddleware):
    """No-op passthrough in Phase 1 — kept as an explicit extension point."""

    async def dispatch(self, request: Request, call_next):
        # TODO(phase-2): enforce per-IP / per-user limits via Redis token bucket.
        return await call_next(request)
