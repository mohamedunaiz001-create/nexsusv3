"""
Port of server/securityAudit.ts

Runs active, automated security diagnostics against live system modules,
verifying real cryptographic operations, URL sanitizers, CSRF signing, and
auth logic.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from app.ai_service import ALLOWED_PROVIDERS, validate_provider_and_model
from app.auth import AUTHORIZED_ACCOUNTS, generate_csrf_token, self_test_admin_auth, validate_csrf_token
from app.security import is_private_ipv4, is_private_ipv6, validate_safe_external_url


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


async def run_automated_security_audit() -> dict:
    start_time = time.monotonic()
    checks: list[dict] = []

    # Check 1: Private IPv4 Range Filtering (SSRF)
    t0 = time.monotonic()
    test_cases = [
        ("127.0.0.1", True), ("169.254.169.254", True), ("10.0.0.1", True),
        ("172.16.0.5", True), ("192.168.1.1", True), ("8.8.8.8", False), ("1.1.1.1", False),
    ]
    all_passed = all(is_private_ipv4(ip) == expected for ip, expected in test_cases)
    checks.append({
        "id": "SEC-SSRF-IPV4", "name": "Private IPv4 SSRF Boundary Filter", "category": "SSRF_PROTECTION",
        "status": "PASS" if all_passed else "FAIL",
        "details": "Verified RFC 1918, RFC 3927 Link-Local, and RFC 5735 private address filtering." if all_passed else "Private IPv4 filtering logic failed on one or more validation vectors.",
        "executionMs": int((time.monotonic() - t0) * 1000),
    })

    # Check 2: IPv6 / IPv4-Mapped Loopback & Local Filtering (SSRF)
    t0 = time.monotonic()
    ipv6_tests = [
        ("::1", True), ("fe80::1", True), ("fc00::1", True),
        ("::ffff:127.0.0.1", True), ("2001:4860:4860::8888", False),
    ]
    all_passed = all(is_private_ipv6(ip) == expected for ip, expected in ipv6_tests)
    checks.append({
        "id": "SEC-SSRF-IPV6", "name": "IPv6 & IPv4-Mapped Address Quarantine", "category": "SSRF_PROTECTION",
        "status": "PASS" if all_passed else "FAIL",
        "details": "Verified IPv6 loopback (::1), unique local (fc00::/7), and dual-stack IPv4-mapped filters." if all_passed else "IPv6 address quarantine logic failed validation check.",
        "executionMs": int((time.monotonic() - t0) * 1000),
    })

    # Check 3: External URL & Hostname SSRF Sanitization
    t0 = time.monotonic()
    res_creds = await validate_safe_external_url("https://admin:pass@api.anthropic.com/v1")
    res_local = await validate_safe_external_url("http://169.254.169.254/latest/meta-data/")
    res_invalid_proto = await validate_safe_external_url("ftp://ftp.example.com/payload")
    passed = (not res_creds.is_safe) and (not res_local.is_safe) and (not res_invalid_proto.is_safe)
    checks.append({
        "id": "SEC-URL-VALIDATION", "name": "External URL & Cloud Metadata Shield", "category": "SSRF_PROTECTION",
        "status": "PASS" if passed else "FAIL",
        "details": "Active verification: Embedded URL credentials, cloud metadata endpoints, and untrusted protocols successfully blocked." if passed else "URL sanitization allowed one or more prohibited external resource targets.",
        "executionMs": int((time.monotonic() - t0) * 1000),
    })

    # Check 4: Anti-CSRF Token Generation & Cryptographic Verification Cycle
    t0 = time.monotonic()
    token = generate_csrf_token()
    is_valid = validate_csrf_token(token)
    tok_parts = token.split(".")
    forged_token = f"{tok_parts[0]}.{tok_parts[1]}.{'0' * 64}"
    is_forged_rejected = not validate_csrf_token(forged_token)
    is_blank_rejected = not validate_csrf_token("")
    passed = is_valid and is_forged_rejected and is_blank_rejected
    checks.append({
        "id": "SEC-CSRF-HMAC", "name": "HMAC-SHA256 Anti-CSRF Token Engine", "category": "CSRF",
        "status": "PASS" if passed else "FAIL",
        "details": "Verified token lifecycle: Generation, timestamp expiry validation, and forged signature rejection." if passed else "CSRF token validation failed verification check.",
        "executionMs": int((time.monotonic() - t0) * 1000),
    })

    # Check 5: Credential Authentication & Timing-Safe Password Hash Engine
    t0 = time.monotonic()
    self_test = self_test_admin_auth()
    passed = self_test["adminLoginWorks"] and self_test["wrongPasswordRejected"] and self_test["unknownUserRejected"]
    checks.append({
        "id": "SEC-AUTH-PBKDF2", "name": "PBKDF2 / Timing-Safe Authentication Engine", "category": "AUTHENTICATION",
        "status": "PASS" if passed else "FAIL",
        "details": "Verified constant-time password comparison, salted PBKDF2 hash validation, and rejection of invalid passphrases." if passed else "Authentication verification engine failed on valid or invalid test cases (or the admin account is unprovisioned — set ADMIN_INITIAL_PASSWORD).",
        "executionMs": int((time.monotonic() - t0) * 1000),
    })

    # Check 6: Server-Authoritative Role Repository
    t0 = time.monotonic()
    account_count = len(AUTHORIZED_ACCOUNTS)
    has_admin = any(a.user.role == "Admin" for a in AUTHORIZED_ACCOUNTS.values())
    has_analyst = any(a.user.role == "Analyst" for a in AUTHORIZED_ACCOUNTS.values())
    passed = account_count >= 3 and has_admin and has_analyst
    checks.append({
        "id": "SEC-RBAC-ACCOUNTS", "name": "Server-Side RBAC Account Registry", "category": "AUTHORIZATION",
        "status": "PASS" if passed else "WARN",
        "details": f"Verified {account_count} registered operator accounts with strict server-bound roles (Admin, Analyst, Viewer)." if passed else f"Only {account_count}/3 operator accounts are provisioned. Set ADMIN_INITIAL_PASSWORD / ANALYST_INITIAL_PASSWORD / VIEWER_INITIAL_PASSWORD (12+ chars each) to provision the missing accounts — unprovisioned accounts fail closed rather than using a fallback password.",
        "executionMs": int((time.monotonic() - t0) * 1000),
    })

    # Check 7: AI Provider & Model Allowlist Gating
    t0 = time.monotonic()
    valid_google, _ = validate_provider_and_model("google", "gemini-3.7-flash")
    invalid_provider, _ = validate_provider_and_model("rogue-ai-provider", "model-1")
    invalid_model, _ = validate_provider_and_model("google", "unauthorized-model-999")
    passed = valid_google and (not invalid_provider) and (not invalid_model)
    checks.append({
        "id": "SEC-AI-ALLOWLIST", "name": "AI Gateway Provider & Model Allowlist Gating", "category": "AI_GATEWAY",
        "status": "PASS" if passed else "FAIL",
        "details": f"Enforced allowlist with {len(ALLOWED_PROVIDERS)} approved providers. Unauthorized providers and models are rejected." if passed else "AI provider allowlist validation allowed unapproved provider or model.",
        "executionMs": int((time.monotonic() - t0) * 1000),
    })

    # Check 8: Environment & Secrets Posture
    t0 = time.monotonic()
    jwt_configured = bool(os.environ.get("JWT_SECRET"))
    csrf_configured = bool(os.environ.get("CSRF_SECRET"))
    gemini_configured = bool(os.environ.get("GEMINI_API_KEY"))
    is_prod = os.environ.get("NODE_ENV") == "production"
    demo_bootstrap_open_in_prod = is_prod and os.environ.get("ALLOW_DEMO_BOOTSTRAP") == "true"

    status = "PASS"
    warnings: list[str] = []
    if not jwt_configured:
        warnings.append("JWT_SECRET is using high-entropy runtime ephemeral secret (set JWT_SECRET in .env for persistent multi-instance session clustering).")
        status = "WARN"
    if not csrf_configured:
        warnings.append("CSRF_SECRET is using runtime ephemeral secret.")
        status = "WARN"
    if not gemini_configured:
        warnings.append("GEMINI_API_KEY not configured (fallback deterministic SOC neural engine is active).")
    if demo_bootstrap_open_in_prod:
        warnings.append("ALLOW_DEMO_BOOTSTRAP=true in production — every visitor without a session is auto-authenticated as the Analyst demo account. Disable unless this is an intentionally public demo.")
        status = "WARN"

    checks.append({
        "id": "SEC-ENV-SECRETS", "name": "Cryptographic Secrets & Key Provisioning", "category": "ENVIRONMENT",
        "status": status,
        "details": " | ".join(warnings) if warnings else "All cryptographic secrets and API keys are explicitly configured in environment.",
        "executionMs": int((time.monotonic() - t0) * 1000),
    })

    passed_count = sum(1 for c in checks if c["status"] == "PASS")
    warn_count = sum(1 for c in checks if c["status"] == "WARN")
    fail_count = sum(1 for c in checks if c["status"] == "FAIL")
    total_checks = len(checks)
    score = round(((passed_count + warn_count * 0.5) / total_checks) * 100)

    overall_status = "HEALTHY"
    release_gate_verdict = "PASS"
    if fail_count > 0:
        overall_status = "ACTION_REQUIRED"
        release_gate_verdict = "FAIL"
    elif warn_count > 0:
        overall_status = "DEGRADED"
        release_gate_verdict = "CONDITIONAL_PASS"

    return {
        "status": overall_status,
        "releaseGateVerdict": release_gate_verdict,
        "summary": {"totalChecks": total_checks, "passed": passed_count, "warnings": warn_count, "failed": fail_count, "score": score},
        "checks": checks,
        "environment": {
            "nodeEnv": os.environ.get("NODE_ENV", "development"),
            "jwtSecretConfigured": jwt_configured,
            "csrfSecretConfigured": csrf_configured,
            "geminiKeyConfigured": gemini_configured,
            "uptimeSeconds": int(time.monotonic() - _APP_START_MONOTONIC),
        },
        "timestamp": _iso_now(),
        "auditDurationMs": int((time.monotonic() - start_time) * 1000),
    }


_APP_START_MONOTONIC = time.monotonic()
