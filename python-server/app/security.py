"""
Port of server/security.ts

Strict SSRF protection, log sanitization, a redacting structured logger,
and a helper for consistent, non-leaky error responses.
"""
from __future__ import annotations

import asyncio
import json
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlsplit

from fastapi.responses import JSONResponse


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def is_private_ipv4(ip: str) -> bool:
    """Checks whether an IPv4 address string falls into a private or reserved network range."""
    parts_raw = ip.split(".")
    if len(parts_raw) != 4:
        return True  # Invalid format treated as unsafe
    try:
        parts = [int(p) for p in parts_raw]
    except ValueError:
        return True
    if any(p < 0 or p > 255 for p in parts):
        return True

    a, b = parts[0], parts[1]

    if a == 0:
        return True  # 0.0.0.0/8 (Current network)
    if a == 10:
        return True  # 10.0.0.0/8 (Private-Use)
    if a == 100 and 64 <= b <= 127:
        return True  # 100.64.0.0/10 (Shared Address Space)
    if a == 127:
        return True  # 127.0.0.0/8 (Loopback)
    if a == 169 and b == 254:
        return True  # 169.254.0.0/16 (Link-Local & Cloud Metadata e.g. 169.254.169.254)
    if a == 172 and 16 <= b <= 31:
        return True  # 172.16.0.0/12 (Private-Use)
    if a == 192 and b == 0 and parts[2] == 0:
        return True  # 192.0.0.0/24 (IETF Protocol Assignments)
    if a == 192 and b == 0 and parts[2] == 2:
        return True  # 192.0.2.0/24 (TEST-NET-1)
    if a == 192 and b == 168:
        return True  # 192.168.0.0/16 (Private-Use)
    if a == 198 and b in (18, 19):
        return True  # 198.18.0.0/15 (Benchmarking)
    if a == 198 and b == 51 and parts[2] == 100:
        return True  # 198.51.100.0/24 (TEST-NET-2)
    if a == 203 and b == 0 and parts[2] == 113:
        return True  # 203.0.113.0/24 (TEST-NET-3)
    if a >= 224:
        return True  # 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)

    return False


def is_private_ipv6(ip: str) -> bool:
    """Checks whether an IPv6 address string is private/loopback/reserved."""
    clean_ip = ip.lower()

    if clean_ip in ("::1", "::"):
        return True

    # IPv4-mapped IPv6 (::ffff:127.0.0.1)
    if clean_ip.startswith("::ffff:"):
        ipv4 = clean_ip.replace("::ffff:", "")
        return is_private_ipv4(ipv4)

    if clean_ip.startswith("fc") or clean_ip.startswith("fd"):
        return True  # fc00::/7 (Unique local)
    if clean_ip.startswith(("fe8", "fe9", "fea", "feb")):
        return True  # fe80::/10 (Link-local)
    if clean_ip.startswith("ff"):
        return True  # ff00::/8 (Multicast)

    return False


class SafeUrlResult:
    def __init__(self, is_safe: bool, reason: Optional[str] = None, parsed_url: Optional[Any] = None):
        self.is_safe = is_safe
        self.reason = reason
        self.parsed_url = parsed_url


async def _dns_lookup_all(hostname: str) -> list[tuple[int, str]]:
    """Resolves a hostname to a list of (family, address) tuples, mirroring Node's dns.lookup(..., {all:true})."""
    loop = asyncio.get_event_loop()

    def _resolve():
        infos = socket.getaddrinfo(hostname, None)
        results = []
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                results.append((4, sockaddr[0]))
            elif family == socket.AF_INET6:
                results.append((6, sockaddr[0]))
        return results

    return await loop.run_in_executor(None, _resolve)


async def validate_safe_external_url(raw_url: str, allow_local_dev: bool = False) -> SafeUrlResult:
    """
    Strict SSRF protection and URL validation.
    Verifies protocol, credentials, hostnames, and performs DNS resolution to
    guarantee non-internal destinations.
    """
    try:
        parsed = urlsplit(raw_url)
    except Exception as err:  # pragma: no cover - urlsplit rarely raises
        return SafeUrlResult(False, reason=f"Malformed URL structure: {err}")

    if not parsed.scheme or not parsed.netloc:
        return SafeUrlResult(False, reason="Malformed URL structure: missing scheme or host.")

    # 1. Strict Protocol Check
    if parsed.scheme not in ("https", "http"):
        return SafeUrlResult(False, reason=f"Unallowed protocol: {parsed.scheme}:. Only HTTPS (and restricted HTTP) is supported.")

    # 2. Disallow credentials embedded in URL (e.g., http://user:pass@host)
    if parsed.username or parsed.password:
        return SafeUrlResult(False, reason="Credentials in URL are strictly prohibited.")

    # 3. Port restrictions
    port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)
    allowed_ports = [80, 443, 8000, 8080, 8443, 11434]
    if port not in allowed_ports:
        return SafeUrlResult(False, reason=f"Destination port {port} is outside the allowed list ({', '.join(map(str, allowed_ports))}).")

    hostname = (parsed.hostname or "").lower()

    # 4. Block explicit loopback/metadata hostnames
    blocked_hostnames = ["localhost", "metadata.google.internal", "instance-data", "169.254.169.254"]
    if not allow_local_dev and (hostname in blocked_hostnames or hostname.endswith(".internal") or hostname.endswith(".local")):
        return SafeUrlResult(False, reason=f"Access to internal hostname '{hostname}' is blocked.")

    # 5. DNS Resolution and IP Address Validation
    try:
        addresses = await _dns_lookup_all(hostname)
        if not addresses:
            return SafeUrlResult(False, reason=f"DNS lookup failed for hostname '{hostname}'.")

        for family, address in addresses:
            if family == 4:
                if is_private_ipv4(address):
                    if not allow_local_dev or not address.startswith("127."):
                        return SafeUrlResult(False, reason=f"Hostname '{hostname}' resolves to private IP: {address}. SSRF blocked.")
            elif family == 6:
                if is_private_ipv6(address):
                    if not allow_local_dev or address != "::1":
                        return SafeUrlResult(False, reason=f"Hostname '{hostname}' resolves to private IPv6: {address}. SSRF blocked.")
    except socket.gaierror as dns_err:
        return SafeUrlResult(False, reason=f"DNS resolution error: {dns_err}")

    return SafeUrlResult(True, parsed_url=parsed)


_SENSITIVE_KEYS = ("apikey", "api_key", "authorization", "token", "secret", "password", "cookie", "set-cookie")


def sanitize_log_data(data: Any) -> Any:
    """Sanitizes logs to prevent accidental leakage of API keys, Authorization headers, and secrets."""
    if data is None or not isinstance(data, (dict, list)):
        return data

    if isinstance(data, list):
        return [sanitize_log_data(v) for v in data]

    clean: dict[str, Any] = {}
    for key, value in data.items():
        if any(sk in key.lower() for sk in _SENSITIVE_KEYS):
            clean[key] = "[REDACTED_SECRET]"
        elif isinstance(value, (dict, list)):
            clean[key] = sanitize_log_data(value)
        elif isinstance(value, str) and len(value) > 500:
            clean[key] = f"{value[:100]}... [TRUNCATED {len(value)} BYTES]"
        else:
            clean[key] = value
    return clean


class _SafeLogger:
    """Safe logger that automatically redacts sensitive data and formats structured JSON logs."""

    def info(self, msg: str, meta: Optional[dict] = None) -> None:
        print(f"[INFO] {_iso_now()} - {msg}", json.dumps(sanitize_log_data(meta or {}), default=str))

    def warn(self, msg: str, meta: Optional[dict] = None) -> None:
        print(f"[WARN] {_iso_now()} - {msg}", json.dumps(sanitize_log_data(meta or {}), default=str))

    def error(self, msg: str, meta: Optional[dict] = None) -> None:
        print(f"[ERROR] {_iso_now()} - {msg}", json.dumps(sanitize_log_data(meta or {}), default=str))


safe_logger = _SafeLogger()


def send_secure_error(status_code: int, message: str, code: str = "SECURITY_ERROR", meta: Optional[dict] = None) -> JSONResponse:
    """Formats a secure, production-ready error response that never leaks stack traces or internal filesystem paths."""
    request_id = str(uuid.uuid4())
    safe_logger.error(f"Error response sent: {code} - {message}", {"requestId": request_id, "statusCode": status_code, "code": code, **(meta or {})})
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error": message,
            "code": code,
            "requestId": request_id,
            "timestamp": _iso_now(),
        },
    )
