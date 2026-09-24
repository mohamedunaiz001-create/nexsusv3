"""
Port of server/tools/registry.ts

Tool Registry — the heart of the Tool Integration system.

This is a static, hand-curated list of supported cybersecurity tools and
the capabilities each one exposes. Nothing else in NEXSUS talks to a
vendor API directly; it only asks the registry "who can do X.lookup?" and
the Tool Gateway (./gateway.py) takes it from there.

Adding a new tool = add one entry here + one adapter module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ToolCapabilityDef:
    id: str
    label: str
    description: str


CAPABILITY_LABELS: dict[str, str] = {
    "hash.lookup": "Hash Lookup",
    "ip.lookup": "IP Lookup",
    "domain.lookup": "Domain Lookup",
    "url.lookup": "URL Lookup",
    "ip.reputation": "IP Reputation",
    "ip.report": "IP Report",
    "host.lookup": "Host Lookup",
    "port.lookup": "Port Lookup",
    "threat.lookup": "Threat Lookup",
}


@dataclass
class ToolDefinition:
    id: str
    name: str
    vendor: str
    category: str  # 'Threat Intelligence' | 'Network Intelligence' | 'IP Reputation'
    description: str
    docsUrl: str
    defaultBaseUrl: str
    allowedHosts: list[str]
    authType: str  # 'api_key' | 'api_key_header'
    capabilities: list[ToolCapabilityDef]
    planLimits: dict  # {'free': {...}, 'premium': {...}}
    authHeaderName: Optional[str] = None


TOOL_REGISTRY: list[ToolDefinition] = [
    ToolDefinition(
        id="virustotal", name="VirusTotal", vendor="Google (Chronicle)", category="Threat Intelligence",
        description="Multi-engine hash, URL, domain, and IP reputation lookups against 70+ AV/EDR vendors.",
        docsUrl="https://docs.virustotal.com/reference/overview",
        defaultBaseUrl="https://www.virustotal.com/api/v3",
        allowedHosts=["www.virustotal.com"],
        authType="api_key_header", authHeaderName="x-apikey",
        planLimits={
            "free": {"requestsPerMinute": 4, "note": "Public API key: 4 req/min, 500 req/day, ~15.5K/month."},
            "premium": {"requestsPerMinute": 240, "note": "Premium/Enterprise key: burst-tolerant, high daily quota per your contract."},
        },
        capabilities=[
            ToolCapabilityDef("hash.lookup", "Hash Lookup", "SHA256/SHA1/MD5 verdict + engine detections"),
            ToolCapabilityDef("ip.lookup", "IP Lookup", "IP reputation, ASN, and related detections"),
            ToolCapabilityDef("domain.lookup", "Domain Lookup", "Domain reputation and categorization"),
            ToolCapabilityDef("url.lookup", "URL Lookup", "URL scan verdict across AV engines"),
        ],
    ),
    ToolDefinition(
        id="otx", name="AlienVault OTX", vendor="AT&T Cybersecurity (LevelBlue)", category="Threat Intelligence",
        description="Open Threat Exchange pulse data — community-sourced IOCs, threat actor attribution, and campaign context.",
        docsUrl="https://otx.alienvault.com/api",
        defaultBaseUrl="https://otx.alienvault.com/api/v1",
        allowedHosts=["otx.alienvault.com"],
        authType="api_key_header", authHeaderName="X-OTX-API-KEY",
        planLimits={
            "free": {"requestsPerMinute": 10, "note": "Standard OTX account — generous but unpublished soft limit; kept conservative here."},
            "premium": {"requestsPerMinute": 60, "note": "Enterprise/partner account with a raised throughput allowance."},
        },
        capabilities=[
            ToolCapabilityDef("ip.lookup", "IP Lookup", "IP reputation and associated pulses"),
            ToolCapabilityDef("domain.lookup", "Domain Lookup", "Domain reputation and associated pulses"),
            ToolCapabilityDef("threat.lookup", "Threat Lookup", "Pulse / campaign / actor context for an indicator"),
        ],
    ),
    ToolDefinition(
        id="shodan", name="Shodan", vendor="Shodan", category="Network Intelligence",
        description="Internet-wide host and service scanning — exposed ports, banners, and vulnerabilities for an IP.",
        docsUrl="https://developer.shodan.io/api",
        defaultBaseUrl="https://api.shodan.io",
        allowedHosts=["api.shodan.io"],
        authType="api_key",
        planLimits={
            "free": {"requestsPerMinute": 10, "note": "Freelancer/dev key — limited query credits, roughly 1 req/sec sustained."},
            "premium": {"requestsPerMinute": 120, "note": "Small Business/Corporate plan — higher query-credit allotment and throughput."},
        },
        capabilities=[
            ToolCapabilityDef("ip.lookup", "IP Lookup", "Open ports, banners, and org info for a host"),
            ToolCapabilityDef("host.lookup", "Host Lookup", "Full host profile including vulnerabilities"),
            ToolCapabilityDef("port.lookup", "Port Lookup", "Exposed services on a given host"),
        ],
    ),
    ToolDefinition(
        id="abuseipdb", name="AbuseIPDB", vendor="AbuseIPDB LLC", category="IP Reputation",
        description="Crowd-sourced IP abuse reports — confidence score, report history, and ISP/usage-type context.",
        docsUrl="https://docs.abuseipdb.com/",
        defaultBaseUrl="https://api.abuseipdb.com/api/v2",
        allowedHosts=["api.abuseipdb.com"],
        authType="api_key_header", authHeaderName="Key",
        planLimits={
            "free": {"requestsPerMinute": 15, "note": "Free key — capped at 1,000 checks/day."},
            "premium": {"requestsPerMinute": 90, "note": "Subscriber key — substantially higher daily check allowance."},
        },
        capabilities=[
            ToolCapabilityDef("ip.lookup", "IP Lookup", "Abuse confidence score and report summary"),
            ToolCapabilityDef("ip.reputation", "IP Reputation", "Abuse confidence score and report summary"),
            ToolCapabilityDef("ip.report", "IP Report", "Full historical abuse report list for an IP"),
        ],
    ),
]

_REGISTRY_BY_ID: dict[str, ToolDefinition] = {t.id: t for t in TOOL_REGISTRY}


def get_tool_definition(tool_id: str) -> Optional[ToolDefinition]:
    return _REGISTRY_BY_ID.get(tool_id)


def find_tools_by_capability(capability: str) -> list[ToolDefinition]:
    """Finds every tool definition that exposes a given capability, in registry order (used as the default resolution priority)."""
    return [t for t in TOOL_REGISTRY if any(c.id == capability for c in t.capabilities)]
