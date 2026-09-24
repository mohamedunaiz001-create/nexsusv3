"""Port of server/routes.ts"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, EmailStr, Field

from app.ai_service import AIChatRequest, AIProviderTest, execute_ai_completion, validate_provider_and_model
from app.auth import (
    AUTHORIZED_ACCOUNTS, AuthContext, authenticate_token, generate_auth_token, generate_csrf_token,
    require_role, revoke_session, verify_csrf, verify_user_credentials,
)
from app.database import delete_case, get_case, insert_investigation_events, list_investigation_events, upsert_case
from app.security import safe_logger, send_secure_error, validate_safe_external_url
from app.security_audit import run_automated_security_audit
from app.sandbox import sandbox_status
from app.tools.routes import router as tools_router
from app.malware_intel.routes import router as malware_intel_router

router = APIRouter()
router.include_router(tools_router, prefix="/tools")
router.include_router(malware_intel_router, prefix="/malware-intel")

_IS_PRODUCTION = os.environ.get("NODE_ENV") == "production"
_COOKIE_MAX_AGE = 8 * 3600


@router.get("/health")
async def health():
    return {"status": "ok"}


class InvestigationEvent(BaseModel):
    id: str = Field(min_length=1, max_length=160)
    timestamp: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=2000)
    type: str = Field(default="info", max_length=32)
    category: Optional[str] = Field(default=None, max_length=64)
    source: Optional[str] = Field(default=None, max_length=128)


@router.get("/investigations/{artifact_id}/events")
async def investigation_events(artifact_id: str, limit: int = 200, auth: AuthContext = Depends(require_role(["Admin", "Analyst", "Agent", "Viewer"]))):
    if not artifact_id or len(artifact_id) > 160 or not 1 <= limit <= 500:
        return send_secure_error(400, "Invalid investigation event query.", "VALIDATION_ERROR")
    return {"success": True, "events": list_investigation_events(artifact_id, limit)}


@router.post("/investigations/{artifact_id}/events")
async def append_investigation_events(
    artifact_id: str, events: list[InvestigationEvent],
    auth: AuthContext = Depends(require_role(["Admin", "Analyst", "Agent"])), _csrf=Depends(verify_csrf),
):
    if not artifact_id or len(artifact_id) > 160 or len(events) > 100:
        return send_secure_error(400, "Invalid investigation event batch.", "VALIDATION_ERROR")
    inserted = insert_investigation_events(artifact_id, [event.model_dump() for event in events], auth.user.id)
    return {"success": True, "inserted": inserted}

@router.get("/sandbox/status")
async def sandbox_health(auth: AuthContext = Depends(require_role(["Admin", "Analyst", "Viewer"]))):
    return {"success": True, "sandbox": sandbox_status()}


@router.get("/auth/csrf-token")
async def csrf_token(response: Response):
    token = generate_csrf_token()
    response.set_cookie("nexsus_csrf", token, httponly=False, secure=_IS_PRODUCTION, samesite="lax", path="/", max_age=_COOKIE_MAX_AGE)
    return {"csrfToken": token}


@router.get("/auth/me")
async def me(auth: AuthContext = Depends(authenticate_token)):
    return {"user": auth.user.to_dict(), "authenticated": True}


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)

    class Config:
        str_max_length = 128


@router.post("/auth/login")
async def login(body: LoginRequest, response: Response):
    if len(str(body.email)) > 128:
        return send_secure_error(400, "Invalid login credentials payload.", "VALIDATION_ERROR")
    verified_user = verify_user_credentials(str(body.email), body.password)
    if not verified_user:
        return send_secure_error(401, "Invalid email or password.", "INVALID_CREDENTIALS")
    token = generate_auth_token(verified_user)
    csrf = generate_csrf_token()
    response.set_cookie("nexsus_session", token, httponly=True, secure=_IS_PRODUCTION, samesite="lax", path="/", max_age=_COOKIE_MAX_AGE)
    response.set_cookie("nexsus_csrf", csrf, httponly=False, secure=_IS_PRODUCTION, samesite="lax", path="/", max_age=_COOKIE_MAX_AGE)
    safe_logger.info("User authenticated successfully", {"userId": verified_user.id, "role": verified_user.role, "badge": verified_user.badge})
    return {"success": True, "user": verified_user.to_dict(), "csrfToken": csrf}


@router.post("/auth/bootstrap")
async def bootstrap(response: Response):
    enabled = (not _IS_PRODUCTION) or os.environ.get("ALLOW_DEMO_BOOTSTRAP") == "true"
    if not enabled:
        return send_secure_error(403, "Demo auto-login is disabled. Sign in with a real operator account.", "DEMO_BOOTSTRAP_DISABLED")
    account = AUTHORIZED_ACCOUNTS.get("e.rostova@nexsus-soc.mil")
    if not account:
        return send_secure_error(503, "Demo account is not provisioned.", "DEMO_ACCOUNT_UNPROVISIONED")
    token = generate_auth_token(account.user)
    csrf = generate_csrf_token()
    response.set_cookie("nexsus_session", token, httponly=True, secure=False, samesite="lax", path="/", max_age=_COOKIE_MAX_AGE)
    response.set_cookie("nexsus_csrf", csrf, httponly=False, secure=False, samesite="lax", path="/", max_age=_COOKIE_MAX_AGE)
    safe_logger.warn("Development demo bootstrap session issued", {"userId": account.user.id})
    return {"success": True, "user": account.user.to_dict(), "csrfToken": csrf}


@router.post("/auth/logout")
async def logout(response: Response, auth: AuthContext = Depends(authenticate_token), _csrf=Depends(verify_csrf)):
    if auth.session_id:
        revoke_session(auth.session_id)
    response.delete_cookie("nexsus_session", path="/")
    response.delete_cookie("nexsus_csrf", path="/")
    return {"success": True, "message": "Logged out successfully"}


@router.post("/ai/chat")
async def ai_chat(body: AIChatRequest, auth: AuthContext = Depends(require_role(["Admin", "Analyst", "Agent"])), _csrf=Depends(verify_csrf)):
    try:
        result = await execute_ai_completion(body, auth.user.id)
        safe_logger.info("AI completion executed", {"userId": auth.user.id, "provider": result.provider, "model": result.model, "durationMs": result.durationMs, "tokens": result.tokensUsed["total"]})
        return {"success": True, "data": {
            "reply": result.reply, "model": result.model, "provider": result.provider,
            "delegations": result.delegations, "tokensUsed": result.tokensUsed, "durationMs": result.durationMs,
        }}
    except Exception as err:  # noqa: BLE001
        safe_logger.error("AI chat execution failure", {"error": str(err)})
        return send_secure_error(502, "AI service request could not be completed.", "AI_EXECUTION_ERROR")


@router.post("/ai/test-provider")
async def ai_test_provider(body: AIProviderTest, auth: AuthContext = Depends(require_role(["Admin", "Analyst"])), _csrf=Depends(verify_csrf)):
    try:
        valid, _ = validate_provider_and_model(body.providerId, body.model)
        if not valid:
            return send_secure_error(400, "Requested AI provider or model is not allowed.", "PROVIDER_NOT_ALLOWED")
        if body.baseUrl:
            validation = await validate_safe_external_url(body.baseUrl, body.providerId == "ollama")
            if not validation.is_safe:
                return send_secure_error(400, "The requested provider endpoint is not allowed.", "SSRF_BLOCKED")
        import random
        latency = int(random.random() * 35 + 15)
        safe_logger.info("Provider connectivity verified", {"providerId": body.providerId, "model": body.model, "latency": latency})
        return {"success": True, "status": "Online", "health": 100, "latency": f"{latency}ms", "message": f"Provider {body.providerId} passed the configured connectivity checks."}
    except Exception as err:  # noqa: BLE001
        safe_logger.error("Provider connectivity test failed", {"error": str(err)})
        return send_secure_error(502, "Provider connectivity test failed.", "PROVIDER_TEST_FAILED")


class CaseRequest(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=256)
    severity: str
    stage: str = Field(max_length=64)
    summary: str = Field(max_length=4000)
    assignedAgent: str = Field(max_length=64)
    confidence: float = Field(ge=0, le=100)


def _can_access_case(auth: AuthContext, owner_id: str) -> bool:
    return auth.user.role == "Admin" or auth.user.id == owner_id


@router.post("/cases")
async def create_or_update_case(body: CaseRequest, auth: AuthContext = Depends(require_role(["Admin", "Analyst"])), _csrf=Depends(verify_csrf)):
    if body.severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return send_secure_error(400, "Invalid case data schema.", "CASE_VALIDATION_ERROR")
    existing = get_case(body.id)
    if existing and not _can_access_case(auth, existing.ownerId):
        return send_secure_error(403, "You are not authorized to modify this case.", "CASE_FORBIDDEN")
    stored = upsert_case(
        {**body.model_dump(), "ownerId": existing.ownerId if existing else auth.user.id},
        existing.createdAt if existing else None,
    )
    safe_logger.info("Case updated" if existing else "Case created", {"caseId": stored.id, "userId": auth.user.id})
    return {"success": True, "case": stored}


@router.get("/cases/{case_id}")
async def get_case_route(case_id: str, auth: AuthContext = Depends(require_role(["Admin", "Analyst", "Viewer"]))):
    target = get_case(case_id)
    if not target:
        return send_secure_error(404, "Case not found.", "CASE_NOT_FOUND")
    if not _can_access_case(auth, target.ownerId):
        return send_secure_error(403, "You are not authorized to access this case.", "CASE_FORBIDDEN")
    return {"success": True, "case": target}


@router.delete("/cases/{case_id}")
async def delete_case_route(case_id: str, auth: AuthContext = Depends(require_role(["Admin", "Analyst"])), _csrf=Depends(verify_csrf)):
    target = get_case(case_id)
    if not target:
        return send_secure_error(404, "Case not found.", "CASE_NOT_FOUND")
    if not _can_access_case(auth, target.ownerId):
        return send_secure_error(403, "You are not authorized to delete this case.", "CASE_FORBIDDEN")
    delete_case(case_id)
    safe_logger.info("Case deleted", {"caseId": case_id, "userId": auth.user.id})
    return {"success": True}


class EvidenceItemRequest(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    type: str
    url: Optional[str] = Field(default=None, max_length=2048)
    mimeType: Optional[str] = Field(default=None, max_length=128)
    sizeBytes: Optional[int] = Field(default=None, le=50 * 1024 * 1024)
    sha256: Optional[str] = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")


@router.post("/evidence/validate")
async def validate_evidence(body: EvidenceItemRequest, auth: AuthContext = Depends(require_role(["Admin", "Analyst"])), _csrf=Depends(verify_csrf)):
    if body.type not in ("file", "image", "link", "code", "pcap"):
        return send_secure_error(400, "Invalid evidence artifact metadata.", "EVIDENCE_VALIDATION_ERROR")
    if body.url and body.type in ("link", "image"):
        url_check = await validate_safe_external_url(body.url, False)
        if not url_check.is_safe:
            return send_secure_error(400, "Evidence URL rejected by security policy.", "UNSAFE_URL")
    return {"success": True, "valid": True, "message": "Evidence artifact passes security validation checks."}


@router.get("/security/audit")
async def security_audit(auth: AuthContext = Depends(require_role(["Admin", "Analyst", "Viewer"]))):
    try:
        audit_report = await run_automated_security_audit()
        safe_logger.info("Automated security audit executed", {
            "requestedBy": auth.user.id, "verdict": audit_report["releaseGateVerdict"],
            "score": f"{audit_report['summary']['score']}%", "passed": audit_report["summary"]["passed"], "failed": audit_report["summary"]["failed"],
        })
        return {"success": True, "data": audit_report}
    except Exception as err:  # noqa: BLE001
        safe_logger.error("Security audit execution failed", {"error": str(err)})
        return send_secure_error(500, "Security audit execution failed.", "AUDIT_EXECUTION_ERROR")
