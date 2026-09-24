"""Port of server/tools/adapters/abuseipdb.ts"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

from app.tools.http_client import ToolRequestError, resolve_tool_base_url, safe_tool_fetch
from app.tools.registry import get_tool_definition
from app.tools.types import AdapterExecuteInput, Indicator, NormalizedFinding, NormalizedToolResult

TOOL = get_tool_definition("abuseipdb")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


async def _call_endpoint(path_and_query: str, api_key: str, base_url: str) -> dict:
    return await safe_tool_fetch(f"{base_url}{path_and_query}", headers={TOOL.authHeaderName: api_key})


async def execute(input: AdapterExecuteInput) -> NormalizedToolResult:
    base_url = await resolve_tool_base_url(TOOL, input.credential.baseUrl)
    timestamp = _iso_now()
    if input.action not in ("ip.lookup", "ip.reputation", "ip.report"):
        raise ToolRequestError(f"AbuseIPDB does not support action '{input.action}'.", "UNSUPPORTED_ACTION")

    verbose = "&verbose" if input.action == "ip.report" else ""
    result = await _call_endpoint(f"/check?ipAddress={quote(input.indicatorValue)}&maxAgeInDays=90{verbose}", input.credential.apiKey, base_url)
    status, json_body = result["status"], result["json"]

    if status in (401, 403):
        raise ToolRequestError("AbuseIPDB rejected the API key (unauthorized).", "AUTH_FAILED")
    if status >= 400:
        raise ToolRequestError(f"AbuseIPDB returned HTTP {status}.", "VENDOR_ERROR")

    data = (json_body or {}).get("data")
    score = (data or {}).get("abuseConfidenceScore", 0)
    if data is None:
        verdict = "unknown"
    elif score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "clean"

    findings = [NormalizedFinding(source="abuseipdb", label=f"Abuse confidence score: {score}%")]
    if data:
        if data.get("totalReports"):
            findings.append(NormalizedFinding(source="abuseipdb", label=f"Total reports: {data['totalReports']}"))
        if data.get("isp"):
            findings.append(NormalizedFinding(source="abuseipdb", label=f"ISP: {data['isp']}"))
        if data.get("countryCode"):
            findings.append(NormalizedFinding(source="abuseipdb", label=f"Country: {data['countryCode']}"))

    return NormalizedToolResult(
        tool="abuseipdb", action=input.action, success=True,
        indicator=Indicator(type="ip", value=input.indicatorValue),
        verdict=verdict, confidence=score, findings=findings,
        references=[f"https://www.abuseipdb.com/check/{quote(input.indicatorValue)}"],
        timestamp=timestamp,
    )


async def test_connection(api_key: str, base_url: Optional[str]) -> dict:
    """Lightweight, safe connectivity test — checks a well-known benign IP (Google public DNS)."""
    resolved_base_url = await resolve_tool_base_url(TOOL, base_url)
    result = await _call_endpoint("/check?ipAddress=8.8.8.8&maxAgeInDays=90", api_key, resolved_base_url)
    status, latency_ms = result["status"], result["latencyMs"]
    if status in (401, 403):
        return {"ok": False, "latencyMs": latency_ms, "message": "Authentication failed — check the API key."}
    if status >= 400:
        return {"ok": False, "latencyMs": latency_ms, "message": f"Vendor API returned HTTP {status}."}
    return {"ok": True, "latencyMs": latency_ms, "message": "Connection successful. Authentication valid."}
