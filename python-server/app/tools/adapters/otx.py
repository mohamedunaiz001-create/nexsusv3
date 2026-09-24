"""Port of server/tools/adapters/otx.ts"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.tools.http_client import ToolRequestError, resolve_tool_base_url, safe_tool_fetch
from app.tools.registry import get_tool_definition
from app.tools.types import AdapterExecuteInput, Indicator, NormalizedFinding, NormalizedToolResult

TOOL = get_tool_definition("otx")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


async def _call_endpoint(path_segment: str, api_key: str, base_url: str) -> dict:
    return await safe_tool_fetch(f"{base_url}{path_segment}", headers={TOOL.authHeaderName: api_key})


async def execute(input: AdapterExecuteInput) -> NormalizedToolResult:
    base_url = await resolve_tool_base_url(TOOL, input.credential.baseUrl)
    timestamp = _iso_now()

    if input.action == "ip.lookup":
        section = f"/indicators/IPv4/{input.indicatorValue}/general"
        indicator_type = "ip"
    elif input.action in ("domain.lookup", "threat.lookup"):
        section = f"/indicators/domain/{input.indicatorValue}/general"
        indicator_type = "domain"
    else:
        raise ToolRequestError(f"AlienVault OTX does not support action '{input.action}'.", "UNSUPPORTED_ACTION")

    result = await _call_endpoint(section, input.credential.apiKey, base_url)
    status, json_body = result["status"], result["json"]

    if status in (401, 403):
        raise ToolRequestError("OTX rejected the API key (unauthorized).", "AUTH_FAILED")
    if status == 404:
        return NormalizedToolResult(
            tool="otx", action=input.action, success=True,
            indicator=Indicator(type=indicator_type, value=input.indicatorValue),
            verdict="unknown", confidence=0,
            findings=[NormalizedFinding(source="otx", label="No pulses reference this indicator.")],
            references=[], timestamp=timestamp,
        )
    if status >= 400:
        raise ToolRequestError(f"OTX returned HTTP {status}.", "VENDOR_ERROR")

    pulse_info = (json_body or {}).get("pulse_info") or {}
    pulse_count = pulse_info.get("count", 0)
    pulses = pulse_info.get("pulses") or []

    if pulse_count > 5:
        verdict, confidence = "malicious", 90
    elif pulse_count > 0:
        verdict, confidence = "suspicious", 55
    else:
        verdict, confidence = "clean", 40

    findings = [
        NormalizedFinding(source="otx", label=p.get("name") or "Pulse", detail=", ".join(p["tags"]) if isinstance(p.get("tags"), list) else None)
        for p in pulses[:5]
    ]

    return NormalizedToolResult(
        tool="otx", action=input.action, success=True,
        indicator=Indicator(type=indicator_type, value=input.indicatorValue),
        verdict=verdict, confidence=confidence, findings=findings,
        references=[f"https://otx.alienvault.com/indicator/{'ip' if indicator_type == 'ip' else 'domain'}/{input.indicatorValue}"],
        timestamp=timestamp,
    )


async def test_connection(api_key: str, base_url: Optional[str]) -> dict:
    """Lightweight, safe connectivity test — pulls the authenticated user's own OTX profile."""
    resolved_base_url = await resolve_tool_base_url(TOOL, base_url)
    result = await _call_endpoint("/user/me", api_key, resolved_base_url)
    status, latency_ms = result["status"], result["latencyMs"]
    if status in (401, 403):
        return {"ok": False, "latencyMs": latency_ms, "message": "Authentication failed — check the API key."}
    if status >= 400:
        return {"ok": False, "latencyMs": latency_ms, "message": f"Vendor API returned HTTP {status}."}
    return {"ok": True, "latencyMs": latency_ms, "message": "Connection successful. Authentication valid."}
