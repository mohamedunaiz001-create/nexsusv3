"""Port of server/tools/adapters/shodan.ts"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

from app.tools.http_client import ToolRequestError, resolve_tool_base_url, safe_tool_fetch
from app.tools.registry import get_tool_definition
from app.tools.types import AdapterExecuteInput, Indicator, NormalizedFinding, NormalizedToolResult

TOOL = get_tool_definition("shodan")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _with_key(url: str, api_key: str) -> str:
    joiner = "&" if "?" in url else "?"
    return f"{url}{joiner}key={quote(api_key)}"


async def execute(input: AdapterExecuteInput) -> NormalizedToolResult:
    base_url = await resolve_tool_base_url(TOOL, input.credential.baseUrl)
    timestamp = _iso_now()
    if input.action not in ("ip.lookup", "host.lookup", "port.lookup"):
        raise ToolRequestError(f"Shodan does not support action '{input.action}'.", "UNSUPPORTED_ACTION")

    result = await safe_tool_fetch(_with_key(f"{base_url}/shodan/host/{quote(input.indicatorValue)}", input.credential.apiKey))
    status, json_body = result["status"], result["json"]

    if status in (401, 403):
        raise ToolRequestError("Shodan rejected the API key (unauthorized).", "AUTH_FAILED")
    if status == 404:
        return NormalizedToolResult(
            tool="shodan", action=input.action, success=True,
            indicator=Indicator(type="ip", value=input.indicatorValue),
            verdict="unknown", confidence=0,
            findings=[NormalizedFinding(source="shodan", label="No scan data available for this host.")],
            references=[], timestamp=timestamp,
        )
    if status >= 400:
        raise ToolRequestError(f"Shodan returned HTTP {status}.", "VENDOR_ERROR")

    json_body = json_body or {}
    ports: list[int] = json_body.get("ports") or []
    vulns: list[str] = json_body.get("vulns") or []
    if vulns:
        verdict, confidence = "malicious", 85
    elif len(ports) > 5:
        verdict, confidence = "suspicious", 50
    else:
        verdict, confidence = "clean", 60

    findings = [NormalizedFinding(source="shodan", label=f"Open ports: {', '.join(map(str, ports)) or 'none observed'}")]
    if vulns:
        findings.append(NormalizedFinding(source="shodan", label=f"Known vulnerabilities: {', '.join(vulns[:10])}"))
    if json_body.get("org"):
        findings.append(NormalizedFinding(source="shodan", label=f"Organization: {json_body['org']}"))

    return NormalizedToolResult(
        tool="shodan", action=input.action, success=True,
        indicator=Indicator(type="ip", value=input.indicatorValue),
        verdict=verdict, confidence=confidence, findings=findings,
        references=[f"https://www.shodan.io/host/{quote(input.indicatorValue)}"],
        timestamp=timestamp,
    )


async def test_connection(api_key: str, base_url: Optional[str]) -> dict:
    """Lightweight, safe connectivity test — checks API-key validity and remaining query credits."""
    resolved_base_url = await resolve_tool_base_url(TOOL, base_url)
    result = await safe_tool_fetch(_with_key(f"{resolved_base_url}/api-info", api_key))
    status, latency_ms = result["status"], result["latencyMs"]
    if status in (401, 403):
        return {"ok": False, "latencyMs": latency_ms, "message": "Authentication failed — check the API key."}
    if status >= 400:
        return {"ok": False, "latencyMs": latency_ms, "message": f"Vendor API returned HTTP {status}."}
    return {"ok": True, "latencyMs": latency_ms, "message": "Connection successful. Authentication valid."}
