"""External sandbox integration boundary.

NEXSUS never executes uploaded samples in-process. A separately isolated
service may advertise a health URL and API URL through environment variables;
this module only reports configuration status and deliberately exposes no local
execution primitive.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse


def sandbox_status() -> dict:
    api_url = (os.environ.get("SANDBOX_API_URL") or "").strip()
    health_url = (os.environ.get("SANDBOX_HEALTH_URL") or "").strip()
    configured = bool(api_url and health_url)
    valid_urls = all(urlparse(value).scheme in {"https"} and bool(urlparse(value).netloc) for value in (api_url, health_url)) if configured else False
    return {
        "configured": configured and valid_urls,
        "executionAvailable": False,
        "mode": "external-isolated-service" if configured and valid_urls else "disabled",
        "apiUrlConfigured": bool(api_url),
        "healthUrlConfigured": bool(health_url),
        "reason": "Sandbox execution requires a separately deployed, isolated service; local sample execution is disabled." if not (configured and valid_urls) else "External sandbox is configured but execution requires an approved service adapter.",
    }
