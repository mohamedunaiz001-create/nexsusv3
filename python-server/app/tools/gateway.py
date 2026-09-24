"""
Port of server/tools/gateway.ts

Executes a tool call end-to-end: resolve -> enabled? -> capability supported? ->
permitted? -> credential available? -> rate limit -> validate input -> adapter
execute -> normalize -> log. This is the *only* path anything in NEXSUS
(agent or operator) uses to reach a vendor API.
"""
from __future__ import annotations

import re
import time
from ipaddress import ip_address
from typing import Optional
from urllib.parse import urlparse

from app.database import get_tool_connection, insert_tool_execution_log
from app.security import safe_logger
from app.tools.adapters import get_adapter
from app.tools.crypto import EncryptedPayload, decrypt_secret
from app.tools.registry import ToolDefinition, find_tools_by_capability, get_tool_definition
from app.tools.types import AdapterExecuteInput, DecryptedCredential, NormalizedToolResult


class ToolGatewayError(Exception):
    def __init__(self, message: str, code: str, status: int = 400):
        super().__init__(message)
        self.code = code
        self.status = status


_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")


def _validate_indicator(action: str, value: str) -> None:
    """Validates that the indicator value's shape actually matches what the requested action expects."""
    v = value.strip()
    if not v or len(v) > 2048:
        raise ToolGatewayError("Indicator value is missing or too long.", "INVALID_INDICATOR")
    if action == "hash.lookup":
        if not _HASH_RE.match(v):
            raise ToolGatewayError("Indicator does not look like a valid MD5/SHA1/SHA256 hash.", "INVALID_INDICATOR")
        return
    if action in ("ip.lookup", "ip.reputation", "ip.report", "host.lookup", "port.lookup"):
        try:
            ip_address(v)
        except ValueError:
            raise ToolGatewayError("Indicator does not look like a valid IPv4/IPv6 address.", "INVALID_INDICATOR")
        return
    if action in ("domain.lookup", "threat.lookup"):
        if not _DOMAIN_RE.match(v):
            raise ToolGatewayError("Indicator does not look like a valid domain name.", "INVALID_INDICATOR")
        return
    if action == "url.lookup":
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ToolGatewayError("Indicator does not look like a valid http(s) URL.", "INVALID_INDICATOR")
        return
    raise ToolGatewayError(f"Unrecognized action '{action}'.", "UNSUPPORTED_ACTION")


# Simple in-memory token bucket, per tool — resets every 60s. Sized to the
# connected key's plan (free vs premium) so a free-tier VirusTotal key
# doesn't get hammered past its real quota, while a premium key isn't
# artificially throttled.
_buckets: dict[str, dict] = {}


def _check_rate_limit(tool: ToolDefinition, plan_tier: str) -> None:
    limit = tool.planLimits[plan_tier]["requestsPerMinute"]
    now = time.monotonic()
    bucket = _buckets.get(tool.id)
    if not bucket or now - bucket["windowStart"] > 60.0:
        _buckets[tool.id] = {"count": 1, "windowStart": now}
        return
    if bucket["count"] >= limit:
        raise ToolGatewayError(f"Rate limit reached for {tool.name} ({limit}/min on your {plan_tier} plan). Try again shortly.", "TOOL_RATE_LIMITED", 429)
    bucket["count"] += 1


class ExecuteToolRequest:
    def __init__(
        self, action: str, indicator_value: str, requested_by_agent: str, requested_by_user_id: str,
        tool_id: Optional[str] = None, case_id: Optional[str] = None, is_operator_initiated: bool = False,
    ):
        self.tool_id = tool_id
        self.action = action
        self.indicator_value = indicator_value
        self.requested_by_agent = requested_by_agent
        self.requested_by_user_id = requested_by_user_id
        self.case_id = case_id
        self.is_operator_initiated = is_operator_initiated


def _resolve_tool(req: ExecuteToolRequest) -> ToolDefinition:
    if req.tool_id:
        tool = get_tool_definition(req.tool_id)
        if not tool:
            raise ToolGatewayError(f"Unknown tool '{req.tool_id}'.", "TOOL_NOT_FOUND", 404)
        return tool
    candidates = [
        t for t in find_tools_by_capability(req.action)
        if (conn := get_tool_connection(t.id)) and conn.enabled and conn.credentialCiphertext
    ]
    if not candidates:
        raise ToolGatewayError(f"No connected tool currently supports '{req.action}'.", "CAPABILITY_UNAVAILABLE", 503)
    return candidates[0]


async def execute_tool(req: ExecuteToolRequest) -> NormalizedToolResult:
    started = time.monotonic()
    tool = _resolve_tool(req)
    log_kwargs = dict(
        tool_id=tool.id, action=req.action, requested_by=req.requested_by_agent,
        requested_by_user_id=req.requested_by_user_id, case_id=req.case_id,
    )

    try:
        if not any(c.id == req.action for c in tool.capabilities):
            raise ToolGatewayError(f"{tool.name} does not support capability '{req.action}'.", "CAPABILITY_NOT_SUPPORTED")

        connection = get_tool_connection(tool.id)
        if not connection or not connection.enabled or not connection.credentialCiphertext:
            raise ToolGatewayError(f"{tool.name} is not connected or is disabled.", "TOOL_NOT_CONNECTED", 409)
        if connection.enabledCapabilities and req.action not in connection.enabledCapabilities:
            raise ToolGatewayError(f"Capability '{req.action}' is disabled for {tool.name}.", "CAPABILITY_DISABLED", 403)
        if not req.is_operator_initiated:
            allow_list = connection.allowedAgents
            if allow_list and req.requested_by_agent not in allow_list:
                raise ToolGatewayError(f"Agent '{req.requested_by_agent}' is not permitted to use {tool.name}.", "AGENT_NOT_PERMITTED", 403)

        _check_rate_limit(tool, connection.planTier)
        _validate_indicator(req.action, req.indicator_value)

        adapter = get_adapter(tool.id)
        if not adapter:
            raise ToolGatewayError(f"No adapter registered for tool '{tool.id}'.", "ADAPTER_MISSING", 500)

        api_key = decrypt_secret(EncryptedPayload(
            ciphertext=connection.credentialCiphertext, iv=connection.credentialIv, tag=connection.credentialTag,
        ))

        result = await adapter.execute(AdapterExecuteInput(
            action=req.action, indicatorValue=req.indicator_value.strip(),
            credential=DecryptedCredential(apiKey=api_key, baseUrl=connection.baseUrl),
        ))

        insert_tool_execution_log(
            **log_kwargs, status="SUCCESS", latency_ms=int((time.monotonic() - started) * 1000),
            verdict=result.verdict, error=None,
        )
        return result
    except ToolGatewayError as err:
        is_gateway_denial = err.code in ("AGENT_NOT_PERMITTED", "CAPABILITY_DISABLED", "TOOL_NOT_CONNECTED")
        insert_tool_execution_log(
            **log_kwargs, status="DENIED" if is_gateway_denial else "FAILED",
            latency_ms=int((time.monotonic() - started) * 1000), verdict=None, error=str(err),
        )
        safe_logger.warn("Tool execution failed", {"toolId": tool.id, "action": req.action, "code": err.code, "error": str(err)})
        raise
    except Exception as err:  # noqa: BLE001
        insert_tool_execution_log(
            **log_kwargs, status="FAILED", latency_ms=int((time.monotonic() - started) * 1000), verdict=None, error=str(err),
        )
        safe_logger.warn("Tool execution failed", {"toolId": tool.id, "action": req.action, "error": str(err)})
        raise
