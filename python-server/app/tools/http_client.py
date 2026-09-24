"""
Port of server/tools/http.ts

Resolves and validates the base URL an adapter is allowed to call, and
performs the actual outbound vendor request with a hard timeout and no
following of redirects off the allowlisted host.
"""
from __future__ import annotations

import time
from typing import Optional

import httpx

from app.security import safe_logger, validate_safe_external_url
from app.tools.registry import ToolDefinition


class ToolRequestError(Exception):
    def __init__(self, message: str, code: str = "TOOL_REQUEST_FAILED"):
        super().__init__(message)
        self.code = code


async def resolve_tool_base_url(tool: ToolDefinition, override_base_url: Optional[str]) -> str:
    """
    A caller-supplied base URL override is only ever honored if its hostname
    is on the tool's fixed allowlist (e.g. a regional API endpoint) — this
    closes off using "Base URL" as an SSRF pivot into internal infrastructure.
    """
    candidate = (override_base_url or "").strip() or tool.defaultBaseUrl
    check = await validate_safe_external_url(candidate, False)
    if not check.is_safe:
        raise ToolRequestError(f"Tool endpoint failed security validation: {check.reason}", "SSRF_BLOCKED")
    hostname = (check.parsed_url.hostname or "").lower()
    if hostname not in tool.allowedHosts:
        raise ToolRequestError(f"Endpoint host '{hostname}' is not on the allowed host list for {tool.name}.", "HOST_NOT_ALLOWED")
    return candidate.rstrip("/")


async def safe_tool_fetch(url: str, method: str = "GET", headers: Optional[dict] = None, timeout_s: float = 10.0) -> dict:
    """Performs the actual outbound call with a hard timeout and no follow of unexpected redirects to non-allowlisted hosts."""
    started = time.monotonic()
    req_headers = {"Accept": "application/json", **(headers or {})}
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout_s) as client:
            res = await client.request(method, url, headers=req_headers)
        latency_ms = int((time.monotonic() - started) * 1000)
        if 300 <= res.status_code < 400:
            # Mirrors Node fetch's `redirect: 'error'` — never silently follow a
            # redirect off the allowlisted host.
            raise ToolRequestError("Vendor API returned a redirect, which is rejected for allowlisted-host safety.", "NETWORK_ERROR")
        try:
            body = res.json()
        except Exception:
            body = None
        return {"status": res.status_code, "json": body, "latencyMs": latency_ms}
    except httpx.TimeoutException:
        raise ToolRequestError(f"Request to vendor API timed out after {int(timeout_s * 1000)}ms.", "TIMEOUT")
    except Exception as err:  # noqa: BLE001
        latency_ms = int((time.monotonic() - started) * 1000)
        safe_logger.warn("Tool adapter outbound request failed", {"error": str(err), "latencyMs": latency_ms})
        raise ToolRequestError("Vendor API request failed or was blocked (redirect off the allowed host is rejected).", "NETWORK_ERROR")
