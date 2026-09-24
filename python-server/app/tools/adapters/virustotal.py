"""Port of server/tools/adapters/virustotal.ts"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Optional

from app.tools.http_client import ToolRequestError, resolve_tool_base_url, safe_tool_fetch
from app.tools.registry import get_tool_definition
from app.tools.types import AdapterExecuteInput, Indicator, NormalizedFinding, NormalizedToolResult

TOOL = get_tool_definition("virustotal")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _verdict_from_stats(stats: Optional[dict]) -> tuple[str, float]:
    if not stats:
        return "unknown", 0
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    if malicious > 0:
        return "malicious", min(99, round((malicious / total) * 100) + 40)
    if suspicious > 0:
        return "suspicious", min(80, round((suspicious / total) * 100) + 20)
    return "clean", 90


async def _call_endpoint(path_segment: str, api_key: str, base_url: str) -> dict:
    return await safe_tool_fetch(f"{base_url}{path_segment}", headers={TOOL.authHeaderName: api_key})


async def execute(input: AdapterExecuteInput) -> NormalizedToolResult:
    base_url = await resolve_tool_base_url(TOOL, input.credential.baseUrl)
    timestamp = _iso_now()

    if input.action == "hash.lookup":
        path = f"/files/{input.indicatorValue}"
        indicator_type = "sha256" if len(input.indicatorValue) == 64 else "sha1" if len(input.indicatorValue) == 40 else "md5"
    elif input.action == "ip.lookup":
        path = f"/ip_addresses/{input.indicatorValue}"
        indicator_type = "ip"
    elif input.action == "domain.lookup":
        path = f"/domains/{input.indicatorValue}"
        indicator_type = "domain"
    elif input.action == "url.lookup":
        encoded = base64.urlsafe_b64encode(input.indicatorValue.encode()).decode().rstrip("=")
        path = f"/urls/{encoded}"
        indicator_type = "url"
    else:
        raise ToolRequestError(f"VirusTotal does not support action '{input.action}'.", "UNSUPPORTED_ACTION")

    result = await _call_endpoint(path, input.credential.apiKey, base_url)
    status, json_body = result["status"], result["json"]

    if status in (401, 403):
        raise ToolRequestError("VirusTotal rejected the API key (unauthorized).", "AUTH_FAILED")
    if status == 404:
        return NormalizedToolResult(
            tool="virustotal", action=input.action, success=True,
            indicator=Indicator(type=indicator_type, value=input.indicatorValue),
            verdict="unknown", confidence=0,
            findings=[NormalizedFinding(source="virustotal", label="No record found for this indicator.")],
            references=[], timestamp=timestamp,
        )
    if status >= 400:
        raise ToolRequestError(f"VirusTotal returned HTTP {status}.", "VENDOR_ERROR")

    attributes = ((json_body or {}).get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats")
    verdict, confidence = _verdict_from_stats(stats)
    findings = [NormalizedFinding(source="virustotal", label=f"{label}: {count}") for label, count in (stats or {}).items()]
    reputation = attributes.get("reputation")
    if isinstance(reputation, (int, float)):
        findings.append(NormalizedFinding(source="virustotal", label=f"Community reputation: {reputation}"))

    return NormalizedToolResult(
        tool="virustotal", action=input.action, success=True,
        indicator=Indicator(type=indicator_type, value=input.indicatorValue),
        verdict=verdict, confidence=confidence, findings=findings,
        references=[f"https://www.virustotal.com/gui/search/{input.indicatorValue}"],
        timestamp=timestamp,
    )


async def test_connection(api_key: str, base_url: Optional[str]) -> dict:
    """Lightweight, safe connectivity test — looks up a well-known benign indicator (Google's public DNS IP)."""
    resolved_base_url = await resolve_tool_base_url(TOOL, base_url)
    result = await _call_endpoint("/ip_addresses/8.8.8.8", api_key, resolved_base_url)
    status, latency_ms = result["status"], result["latencyMs"]
    if status in (401, 403):
        return {"ok": False, "latencyMs": latency_ms, "message": "Authentication failed — check the API key."}
    if status >= 400:
        return {"ok": False, "latencyMs": latency_ms, "message": f"Vendor API returned HTTP {status}."}
    return {"ok": True, "latencyMs": latency_ms, "message": "Connection successful. Authentication valid."}
