"""Port of server/tools/routes.ts"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from app.auth import AuthContext, authenticate_token, require_role, verify_csrf
from app.database import (
    disconnect_tool, get_tool_connection, list_tool_execution_logs, record_tool_test_result,
    set_tool_enabled, update_tool_permissions, upsert_tool_credential,
)
from app.security import safe_logger, send_secure_error
from app.tools.adapters import get_adapter
from app.tools.crypto import EncryptedPayload, decrypt_secret, encrypt_secret
from app.tools.gateway import ExecuteToolRequest, ToolGatewayError, execute_tool
from app.tools.http_client import resolve_tool_base_url
from app.tools.registry import CAPABILITY_LABELS, TOOL_REGISTRY, get_tool_definition

router = APIRouter()


def _tool_id_param(tool_id: str) -> str:
    return (tool_id or "").lower().strip()


def _to_public_view(tool_id: str) -> dict:
    """Public (to authenticated operators) view of a tool: definition + connection status, never the credential itself."""
    definition = get_tool_definition(tool_id)
    conn = get_tool_connection(tool_id)
    return {
        "id": definition.id,
        "name": definition.name,
        "vendor": definition.vendor,
        "category": definition.category,
        "description": definition.description,
        "docsUrl": definition.docsUrl,
        "defaultBaseUrl": definition.defaultBaseUrl,
        "authType": definition.authType,
        "capabilities": [{"id": c.id, "label": CAPABILITY_LABELS[c.id], "description": c.description} for c in definition.capabilities],
        "connected": bool(conn and conn.credentialCiphertext),
        "enabled": bool(conn and conn.enabled),
        "baseUrl": conn.baseUrl if conn else None,
        "planTier": conn.planTier if conn else "free",
        "planLimits": definition.planLimits,
        "enabledCapabilities": conn.enabledCapabilities if conn else [],
        "allowedAgents": conn.allowedAgents if conn else [],
        "health": {
            "status": "DISCONNECTED" if not (conn and conn.credentialCiphertext) else ("DEGRADED" if conn.lastTestStatus == "FAILED" else "HEALTHY" if conn.lastTestStatus == "SUCCESS" else "UNKNOWN"),
            "latencyMs": conn.lastTestLatencyMs if conn else None,
            "lastCheckedAt": conn.lastTestAt if conn else None,
            "lastError": conn.lastError if conn else None,
        },
        "connectedBy": conn.connectedBy if conn else None,
        "connectedAt": conn.connectedAt if conn else None,
    }


@router.get("")
@router.get("/")
async def list_tools(auth: AuthContext = Depends(require_role(["Admin", "Analyst", "Viewer"]))):
    return {"success": True, "tools": [_to_public_view(t.id) for t in TOOL_REGISTRY]}


@router.get("/{tool_id}/health")
async def tool_health(tool_id: str, auth: AuthContext = Depends(require_role(["Admin", "Analyst", "Viewer"]))):
    tool_id = _tool_id_param(tool_id)
    if not get_tool_definition(tool_id):
        return send_secure_error(404, "Unknown tool.", "TOOL_NOT_FOUND")
    return {"success": True, "tool": _to_public_view(tool_id)}


class ConnectRequest(BaseModel):
    apiKey: str = Field(min_length=4, max_length=512)
    baseUrl: Optional[str] = Field(default=None, max_length=2048)
    planTier: str = Field(default="free")
    enabledCapabilities: Optional[list[str]] = Field(default=None)


@router.post("/{tool_id}/connect")
async def connect_tool(
    tool_id: str, body: ConnectRequest, request: Request,
    auth: AuthContext = Depends(require_role(["Admin", "Analyst"])), _csrf=Depends(verify_csrf),
):
    tool_id = _tool_id_param(tool_id)
    tool = get_tool_definition(tool_id)
    if not tool:
        return send_secure_error(404, "Unknown tool.", "TOOL_NOT_FOUND")
    if body.planTier not in ("free", "premium"):
        return send_secure_error(400, "Invalid connection payload.", "VALIDATION_ERROR")

    try:
        # Validate the base URL (if a regional override was supplied) before ever storing a credential against it.
        await resolve_tool_base_url(tool, body.baseUrl)
        valid_capability_ids = {c.id for c in tool.capabilities}
        enabled_capabilities = [c for c in (body.enabledCapabilities or [c.id for c in tool.capabilities]) if c in valid_capability_ids]

        payload = encrypt_secret(body.apiKey)
        upsert_tool_credential(
            tool_id=tool_id, base_url=body.baseUrl, auth_type=tool.authType, plan_tier=body.planTier,
            credential_ciphertext=payload.ciphertext, credential_iv=payload.iv, credential_tag=payload.tag,
            enabled_capabilities=enabled_capabilities, connected_by=auth.user.id,
        )

        # Immediately verify the credential works so the UI never shows "Connected" for a bad key.
        adapter = get_adapter(tool_id)
        try:
            test_outcome = await adapter.test_connection(body.apiKey, body.baseUrl)
        except Exception as err:  # noqa: BLE001
            test_outcome = {"ok": False, "latencyMs": 0, "message": str(err) or "Connection test failed."}

        record_tool_test_result(tool_id, "SUCCESS" if test_outcome["ok"] else "FAILED", test_outcome["latencyMs"], None if test_outcome["ok"] else test_outcome["message"])
        safe_logger.info("Tool connected", {"toolId": tool_id, "userId": auth.user.id, "testOk": test_outcome["ok"]})
        return {"success": True, "tool": _to_public_view(tool_id), "test": test_outcome}
    except Exception as err:  # noqa: BLE001
        code = getattr(err, "code", None)
        if code:
            return send_secure_error(400, str(err), code)
        safe_logger.error("Tool connect failed", {"toolId": tool_id, "error": str(err)})
        return send_secure_error(502, "Failed to connect tool.", "TOOL_CONNECT_FAILED")


@router.post("/{tool_id}/test")
async def test_tool(tool_id: str, auth: AuthContext = Depends(require_role(["Admin", "Analyst"])), _csrf=Depends(verify_csrf)):
    tool_id = _tool_id_param(tool_id)
    tool = get_tool_definition(tool_id)
    if not tool:
        return send_secure_error(404, "Unknown tool.", "TOOL_NOT_FOUND")
    connection = get_tool_connection(tool_id)
    if not connection or not connection.credentialCiphertext:
        return send_secure_error(409, "Tool is not connected yet.", "TOOL_NOT_CONNECTED")

    try:
        api_key = decrypt_secret(EncryptedPayload(ciphertext=connection.credentialCiphertext, iv=connection.credentialIv, tag=connection.credentialTag))
        adapter = get_adapter(tool_id)
        outcome = await adapter.test_connection(api_key, connection.baseUrl)
        record_tool_test_result(tool_id, "SUCCESS" if outcome["ok"] else "FAILED", outcome["latencyMs"], None if outcome["ok"] else outcome["message"])
        safe_logger.info("Tool connectivity test executed", {"toolId": tool_id, "userId": auth.user.id, "ok": outcome["ok"]})
        return {"success": True, "test": outcome, "tool": _to_public_view(tool_id)}
    except Exception as err:  # noqa: BLE001
        record_tool_test_result(tool_id, "FAILED", 0, str(err))
        return send_secure_error(502, "Connectivity test failed.", "TOOL_TEST_FAILED")


@router.post("/{tool_id}/enable")
async def enable_tool(tool_id: str, auth: AuthContext = Depends(require_role(["Admin", "Analyst"])), _csrf=Depends(verify_csrf)):
    tool_id = _tool_id_param(tool_id)
    if not get_tool_definition(tool_id):
        return send_secure_error(404, "Unknown tool.", "TOOL_NOT_FOUND")
    connection = get_tool_connection(tool_id)
    if not connection or not connection.credentialCiphertext:
        return send_secure_error(409, "Connect the tool before enabling it.", "TOOL_NOT_CONNECTED")
    set_tool_enabled(tool_id, True)
    safe_logger.info("Tool enabled", {"toolId": tool_id, "userId": auth.user.id})
    return {"success": True, "tool": _to_public_view(tool_id)}


@router.post("/{tool_id}/disable")
async def disable_tool(tool_id: str, auth: AuthContext = Depends(require_role(["Admin", "Analyst"])), _csrf=Depends(verify_csrf)):
    tool_id = _tool_id_param(tool_id)
    if not get_tool_definition(tool_id):
        return send_secure_error(404, "Unknown tool.", "TOOL_NOT_FOUND")
    set_tool_enabled(tool_id, False)
    safe_logger.info("Tool disabled", {"toolId": tool_id, "userId": auth.user.id})
    return {"success": True, "tool": _to_public_view(tool_id)}


@router.delete("/{tool_id}")
async def delete_tool(tool_id: str, auth: AuthContext = Depends(require_role(["Admin"])), _csrf=Depends(verify_csrf)):
    tool_id = _tool_id_param(tool_id)
    if not get_tool_definition(tool_id):
        return send_secure_error(404, "Unknown tool.", "TOOL_NOT_FOUND")
    disconnect_tool(tool_id)
    safe_logger.info("Tool disconnected — credential purged", {"toolId": tool_id, "userId": auth.user.id})
    return {"success": True, "tool": _to_public_view(tool_id)}


class PermissionsRequest(BaseModel):
    allowedAgents: list[str] = Field(default_factory=list, max_length=50)
    enabledCapabilities: list[str] = Field(default_factory=list, max_length=20)


@router.put("/{tool_id}/permissions")
async def update_permissions(tool_id: str, body: PermissionsRequest, auth: AuthContext = Depends(require_role(["Admin"])), _csrf=Depends(verify_csrf)):
    tool_id = _tool_id_param(tool_id)
    tool = get_tool_definition(tool_id)
    if not tool:
        return send_secure_error(404, "Unknown tool.", "TOOL_NOT_FOUND")
    valid_capability_ids = {c.id for c in tool.capabilities}
    enabled_capabilities = [c for c in body.enabledCapabilities if c in valid_capability_ids]
    update_tool_permissions(tool_id, body.allowedAgents, enabled_capabilities)
    safe_logger.info("Tool permissions updated", {"toolId": tool_id, "userId": auth.user.id, "allowedAgents": len(body.allowedAgents), "enabledCapabilities": len(enabled_capabilities)})
    return {"success": True, "tool": _to_public_view(tool_id)}


class ExecuteRequest(BaseModel):
    toolId: Optional[str] = Field(default=None, max_length=64)
    action: str = Field(min_length=1, max_length=64)
    indicatorValue: str = Field(min_length=1, max_length=2048)
    caseId: Optional[str] = Field(default=None, max_length=64)
    requestedByAgent: Optional[str] = Field(default=None, max_length=128)


@router.post("/execute")
async def execute(body: ExecuteRequest, auth: AuthContext = Depends(require_role(["Admin", "Analyst", "Agent"])), _csrf=Depends(verify_csrf)):
    is_operator_initiated = auth.user.role in ("Admin", "Analyst")
    try:
        result = await execute_tool(ExecuteToolRequest(
            tool_id=body.toolId, action=body.action, indicator_value=body.indicatorValue,
            case_id=body.caseId, requested_by_agent=body.requestedByAgent or auth.user.name,
            requested_by_user_id=auth.user.id, is_operator_initiated=is_operator_initiated,
        ))
        return {"success": True, "result": result}
    except ToolGatewayError as err:
        return send_secure_error(err.status, str(err), err.code)
    except Exception as err:  # noqa: BLE001
        safe_logger.error("Tool execution error", {"error": str(err)})
        return send_secure_error(502, "Tool execution failed.", "TOOL_EXECUTION_ERROR")


@router.get("/logs/recent")
async def recent_logs(
    toolId: Optional[str] = Query(default=None), caseId: Optional[str] = Query(default=None), limit: Optional[int] = Query(default=None),
    auth: AuthContext = Depends(require_role(["Admin", "Analyst", "Viewer"])),
):
    logs = list_tool_execution_logs(tool_id=toolId, case_id=caseId, limit=limit)
    return {"success": True, "logs": logs}
