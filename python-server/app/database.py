"""
Port of server/database.ts

Uses Python's built-in sqlite3 (instead of node:sqlite). A single
process-wide connection is shared, guarded by a lock, since sqlite3
connections are not thread-safe by default and FastAPI may run sync
endpoint code across worker threads.
"""
from __future__ import annotations

import json
import os
import random
import sqlite3
import string
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.security import safe_logger

_data_dir = Path(os.environ.get("NEXSUS_DATA_DIR", "").strip() or (Path.cwd() / "data"))
_data_dir.mkdir(parents=True, exist_ok=True)
_db_path = _data_dir / "nexsus.sqlite"

_conn = sqlite3.connect(str(_db_path), check_same_thread=False)
_conn.row_factory = sqlite3.Row
_lock = threading.RLock()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _exec(sql: str, params: tuple = ()) -> sqlite3.Cursor:
    with _lock:
        cur = _conn.execute(sql, params)
        _conn.commit()
        return cur


def _exec_many(sql: str, params_list: list[tuple]) -> int:
    """Bulk insert/update helper — one commit for the whole batch instead of one
    per row, so large dataset ingests don't pay a full fsync per row."""
    if not params_list:
        return 0
    with _lock:
        cur = _conn.executemany(sql, params_list)
        _conn.commit()
        return cur.rowcount


def _query_one(sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
    with _lock:
        cur = _conn.execute(sql, params)
        return cur.fetchone()


def _query_all(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    with _lock:
        cur = _conn.execute(sql, params)
        return cur.fetchall()


with _lock:
    _conn.executescript(
        """
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;
        PRAGMA busy_timeout = 5000;
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY, title TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW')),
            stage TEXT NOT NULL, summary TEXT NOT NULL, assigned_agent TEXT NOT NULL,
            confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
            owner_id TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            jti TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL, revoked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_cases_owner ON cases(owner_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

        CREATE TABLE IF NOT EXISTS investigation_events (
            id TEXT PRIMARY KEY,
            artifact_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            message TEXT NOT NULL,
            event_type TEXT NOT NULL,
            category TEXT,
            source TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_investigation_events_artifact ON investigation_events(artifact_id, timestamp);

        CREATE TABLE IF NOT EXISTS tool_connections (
            tool_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            base_url TEXT,
            auth_type TEXT NOT NULL DEFAULT 'api_key',
            plan_tier TEXT NOT NULL DEFAULT 'free' CHECK (plan_tier IN ('free','premium')),
            credential_ciphertext TEXT,
            credential_iv TEXT,
            credential_tag TEXT,
            enabled_capabilities TEXT NOT NULL DEFAULT '[]',
            allowed_agents TEXT NOT NULL DEFAULT '[]',
            last_test_status TEXT,
            last_test_latency_ms INTEGER,
            last_test_at TEXT,
            last_error TEXT,
            connected_by TEXT,
            connected_at TEXT,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tool_execution_logs (
            id TEXT PRIMARY KEY,
            tool_id TEXT NOT NULL,
            action TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            requested_by_user_id TEXT,
            case_id TEXT,
            status TEXT NOT NULL CHECK (status IN ('SUCCESS','FAILED','DENIED')),
            latency_ms INTEGER NOT NULL DEFAULT 0,
            verdict TEXT,
            error TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tool_logs_tool ON tool_execution_logs(tool_id);
        CREATE INDEX IF NOT EXISTS idx_tool_logs_case ON tool_execution_logs(case_id);
        CREATE INDEX IF NOT EXISTS idx_tool_logs_created ON tool_execution_logs(created_at);

        -- -------------------------------------------------------------
        -- Malware Intelligence Engine (see app/malware_intel/)
        -- -------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS malware_samples (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            sha256 TEXT NOT NULL UNIQUE,
            sha1 TEXT NOT NULL,
            md5 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            file_format TEXT NOT NULL,
            features_json TEXT NOT NULL,
            vector_json TEXT NOT NULL,
            label TEXT CHECK (label IN ('malicious','benign') OR label IS NULL),
            family TEXT,
            verdict TEXT,
            confidence REAL,
            verdict_json TEXT,
            uploaded_by TEXT NOT NULL,
            case_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_malware_samples_created ON malware_samples(created_at);
        CREATE INDEX IF NOT EXISTS idx_malware_samples_family ON malware_samples(family);

        CREATE TABLE IF NOT EXISTS malware_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN ('hash','string','import_hit')),
            pattern TEXT NOT NULL,
            family TEXT,
            severity TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low','medium','high','critical')),
            source TEXT,
            created_by TEXT,
            agent_id TEXT NOT NULL DEFAULT 'malware-analysis',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS malware_reports (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            content_excerpt TEXT,
            extracted_iocs_json TEXT NOT NULL,
            extracted_families_json TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS malware_iocs (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            family TEXT,
            source_report_id TEXT,
            source_sample_id TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(type, value)
        );
        CREATE INDEX IF NOT EXISTS idx_malware_iocs_type ON malware_iocs(type);

        CREATE TABLE IF NOT EXISTS malware_datasets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            content_hash TEXT NOT NULL UNIQUE,
            dataset_type TEXT NOT NULL DEFAULT 'malware_training',
            num_rows INTEGER NOT NULL,
            num_malicious INTEGER NOT NULL,
            num_benign INTEGER NOT NULL,
            num_reference INTEGER NOT NULL DEFAULT 0,
            uploaded_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS malware_dataset_rows (
            id TEXT PRIMARY KEY,
            dataset_id TEXT NOT NULL,
            sample_ref TEXT,
            label TEXT CHECK (label IN ('malicious','benign') OR label IS NULL),
            family TEXT,
            vector_json TEXT,
            vector_source TEXT,
            raw_json TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_malware_dataset_rows_dataset ON malware_dataset_rows(dataset_id);

        CREATE TABLE IF NOT EXISTS malware_model_versions (
            id TEXT PRIMARY KEY,
            version INTEGER NOT NULL,
            weights_json TEXT NOT NULL,
            bias REAL NOT NULL,
            train_accuracy REAL NOT NULL,
            num_samples INTEGER NOT NULL,
            num_malicious INTEGER NOT NULL,
            num_benign INTEGER NOT NULL,
            trained_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_malware_model_versions_created ON malware_model_versions(created_at);
        """
    )
    _conn.commit()


def _ensure_column(table: str, column: str, ddl: str) -> None:
    """Additive migration: adds a column if it doesn't already exist on an existing DB file."""
    existing = _query_all(f"PRAGMA table_info({table})")
    if not any(col["name"] == column for col in existing):
        _exec(f"ALTER TABLE {table} ADD COLUMN {ddl}")


_ensure_column("tool_connections", "plan_tier", "plan_tier TEXT NOT NULL DEFAULT 'free'")
_ensure_column("malware_rules", "agent_id", "agent_id TEXT NOT NULL DEFAULT 'malware-analysis'")
_exec("CREATE INDEX IF NOT EXISTS idx_malware_rules_agent ON malware_rules(agent_id)")

# Seed conservative, explainable high-signal rules once. Operators can add or
# remove rules through the existing rules API; fixed IDs keep this migration idempotent.
_DEFAULT_MALWARE_RULES = (
    ("seed-lolbin-mshta", "LOLBIN: mshta", "string", "mshta.exe", None, "high", "NEXSUS baseline", "system"),
    ("seed-lolbin-regsvr32", "LOLBIN: regsvr32", "string", "regsvr32 /s /n /u /i:", None, "high", "NEXSUS baseline", "system"),
    ("seed-lolbin-bitsadmin", "LOLBIN: bitsadmin transfer", "string", "bitsadmin /transfer", None, "high", "NEXSUS baseline", "system"),
    ("seed-lolbin-certutil", "LOLBIN: certutil URL cache", "string", "certutil -urlcache", None, "high", "NEXSUS baseline", "system"),
    ("seed-process-injection-combo", "Process injection API combination", "import_hit", "VirtualAllocEx+WriteProcessMemory+CreateRemoteThread", None, "critical", "NEXSUS baseline", "system"),
)
for _rule_id, _name, _kind, _pattern, _family, _severity, _source, _created_by in _DEFAULT_MALWARE_RULES:
    _exec(
        "INSERT OR IGNORE INTO malware_rules (id,name,kind,pattern,family,severity,source,created_by,agent_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (_rule_id, _name, _kind, _pattern, _family, _severity, _source, _created_by, "malware-analysis", _iso_now()),
    )


def _migrate_malware_dataset_rows_schema() -> None:
    """One-time structural migration: older builds required every dataset row
    to carry a non-null 'malicious'/'benign' label and a vector. Datasets are
    now accepted from any agent/schema, so unlabeled or unmapped rows are
    kept as reference data instead of being rejected. SQLite can't relax a
    CHECK/NOT NULL constraint in place, so if an existing DB file still has
    the old strict schema this rebuilds the table and preserves prior rows.

    Detection is based on the table's actual stored CREATE TABLE SQL (not
    just the `notnull` PRAGMA flag) so this reliably catches every historical
    variant of the old strict schema, including ones where `label` allowed
    NULL at the column level but a NOT NULL constraint or a stricter CHECK
    was present elsewhere in the definition."""
    row = _query_one("SELECT sql FROM sqlite_master WHERE type='table' AND name='malware_dataset_rows'")
    if row is None:
        return  # table doesn't exist yet — CREATE TABLE above already has the new schema
    current_sql = (row["sql"] or "").lower()
    has_raw_json = "raw_json" in current_sql
    forces_non_null_label = "label" in current_sql and "not null" in current_sql.split("label", 1)[1].split(",", 1)[0]
    if has_raw_json and not forces_non_null_label:
        return  # already on the current, lenient schema — nothing to do
    _exec("ALTER TABLE malware_dataset_rows RENAME TO malware_dataset_rows_old")
    _exec(
        """
        CREATE TABLE malware_dataset_rows (
            id TEXT PRIMARY KEY,
            dataset_id TEXT NOT NULL,
            sample_ref TEXT,
            label TEXT CHECK (label IN ('malicious','benign') OR label IS NULL),
            family TEXT,
            vector_json TEXT,
            vector_source TEXT,
            raw_json TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    old_info = _query_all("PRAGMA table_info(malware_dataset_rows_old)")
    old_cols = {c["name"] for c in old_info}
    select_cols = ", ".join(
        (c if c in old_cols else f"NULL AS {c}")
        for c in ("id", "dataset_id", "sample_ref", "label", "family", "vector_json", "created_at")
    )
    _exec(f"INSERT INTO malware_dataset_rows (id, dataset_id, sample_ref, label, family, vector_json, created_at) "
          f"SELECT {select_cols} FROM malware_dataset_rows_old")
    _exec("DROP TABLE malware_dataset_rows_old")
    _exec("CREATE INDEX IF NOT EXISTS idx_malware_dataset_rows_dataset ON malware_dataset_rows(dataset_id)")
    _conn.commit()
    safe_logger.info("Migrated malware_dataset_rows off the old strict label schema.", {})


_migrate_malware_dataset_rows_schema()
_ensure_column("malware_datasets", "dataset_type", "dataset_type TEXT NOT NULL DEFAULT 'malware_training'")
_ensure_column("malware_datasets", "num_reference", "num_reference INTEGER NOT NULL DEFAULT 0")


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

@dataclass
class DbCase:
    id: str
    title: str
    severity: str
    stage: str
    summary: str
    assignedAgent: str
    confidence: float
    ownerId: str
    createdAt: str
    updatedAt: str


def _row_to_case(row: sqlite3.Row) -> DbCase:
    return DbCase(
        id=row["id"], title=row["title"], severity=row["severity"], stage=row["stage"],
        summary=row["summary"], assignedAgent=row["assigned_agent"], confidence=row["confidence"],
        ownerId=row["owner_id"], createdAt=row["created_at"], updatedAt=row["updated_at"],
    )


def get_case(case_id: str) -> Optional[DbCase]:
    row = _query_one("SELECT * FROM cases WHERE id = ?", (case_id,))
    return _row_to_case(row) if row else None


def upsert_case(input_data: dict, created_at: Optional[str] = None) -> DbCase:
    now = _iso_now()
    _exec(
        """
        INSERT INTO cases (id,title,severity,stage,summary,assigned_agent,confidence,owner_id,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET title=excluded.title,severity=excluded.severity,stage=excluded.stage,
          summary=excluded.summary,assigned_agent=excluded.assigned_agent,confidence=excluded.confidence,updated_at=excluded.updated_at
        """,
        (
            input_data["id"], input_data["title"], input_data["severity"], input_data["stage"],
            input_data["summary"], input_data["assignedAgent"], input_data["confidence"],
            input_data["ownerId"], created_at or now, now,
        ),
    )
    return get_case(input_data["id"])  # type: ignore[return-value]


def delete_case(case_id: str) -> bool:
    cur = _exec("DELETE FROM cases WHERE id = ?", (case_id,))
    return cur.rowcount > 0


def insert_investigation_events(artifact_id: str, events: list[dict], created_by: str) -> int:
    now = _iso_now()
    rows = [
        (
            event["id"], artifact_id, event["timestamp"], event["message"],
            event.get("type", "info"), event.get("category"), event.get("source"), created_by, now,
        )
        for event in events
    ]
    inserted = _exec_many(
        "INSERT OR IGNORE INTO investigation_events "
        "(id,artifact_id,timestamp,message,event_type,category,source,created_by,created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        rows,
    )
    return inserted


def list_investigation_events(artifact_id: str, limit: int = 200) -> list[dict]:
    rows = _query_all(
        "SELECT id, artifact_id, timestamp, message, event_type, category, source "
        "FROM investigation_events WHERE artifact_id = ? ORDER BY timestamp DESC, created_at DESC LIMIT ?",
        (artifact_id, limit),
    )
    return [
        {
            "id": row["id"], "artifactId": row["artifact_id"], "timestamp": row["timestamp"],
            "message": row["message"], "type": row["event_type"], "category": row["category"], "source": row["source"],
        }
        for row in rows
    ]


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def create_session(jti: str, user_id: str, expires_at: str) -> None:
    _exec(
        "INSERT INTO sessions (jti,user_id,created_at,expires_at) VALUES (?,?,?,?)",
        (jti, user_id, _iso_now(), expires_at),
    )


def is_session_active(jti: str) -> bool:
    row = _query_one("SELECT expires_at, revoked_at FROM sessions WHERE jti = ?", (jti,))
    if not row:
        return False
    if row["revoked_at"]:
        return False
    try:
        expires_ts = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")).timestamp()
    except ValueError:
        return False
    return expires_ts * 1000 > time.time() * 1000


def revoke_session(jti: str) -> None:
    _exec("UPDATE sessions SET revoked_at = ? WHERE jti = ? AND revoked_at IS NULL", (_iso_now(), jti))


def revoke_all_user_sessions(user_id: str) -> None:
    _exec("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (_iso_now(), user_id))


def prune_expired_sessions() -> None:
    _exec("DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL", (_iso_now(),))


# ---------------------------------------------------------------------------
# Tool connections & execution logs
# ---------------------------------------------------------------------------

@dataclass
class DbToolConnection:
    toolId: str
    enabled: bool
    baseUrl: Optional[str]
    authType: str
    planTier: str
    credentialCiphertext: Optional[str]
    credentialIv: Optional[str]
    credentialTag: Optional[str]
    enabledCapabilities: list = field(default_factory=list)
    allowedAgents: list = field(default_factory=list)
    lastTestStatus: Optional[str] = None
    lastTestLatencyMs: Optional[int] = None
    lastTestAt: Optional[str] = None
    lastError: Optional[str] = None
    connectedBy: Optional[str] = None
    connectedAt: Optional[str] = None
    updatedAt: str = ""


def _row_to_tool_connection(row: sqlite3.Row) -> DbToolConnection:
    return DbToolConnection(
        toolId=row["tool_id"],
        enabled=bool(row["enabled"]),
        baseUrl=row["base_url"],
        authType=row["auth_type"],
        planTier=row["plan_tier"] if row["plan_tier"] == "premium" else "free",
        credentialCiphertext=row["credential_ciphertext"],
        credentialIv=row["credential_iv"],
        credentialTag=row["credential_tag"],
        enabledCapabilities=json.loads(row["enabled_capabilities"] or "[]"),
        allowedAgents=json.loads(row["allowed_agents"] or "[]"),
        lastTestStatus=row["last_test_status"],
        lastTestLatencyMs=row["last_test_latency_ms"],
        lastTestAt=row["last_test_at"],
        lastError=row["last_error"],
        connectedBy=row["connected_by"],
        connectedAt=row["connected_at"],
        updatedAt=row["updated_at"],
    )


def get_tool_connection(tool_id: str) -> Optional[DbToolConnection]:
    row = _query_one("SELECT * FROM tool_connections WHERE tool_id = ?", (tool_id,))
    return _row_to_tool_connection(row) if row else None


def list_tool_connections() -> list[DbToolConnection]:
    rows = _query_all("SELECT * FROM tool_connections")
    return [_row_to_tool_connection(r) for r in rows]


def upsert_tool_credential(
    tool_id: str, base_url: Optional[str], auth_type: str, plan_tier: str,
    credential_ciphertext: str, credential_iv: str, credential_tag: str,
    enabled_capabilities: list[str], connected_by: str,
) -> DbToolConnection:
    now = _iso_now()
    existing = get_tool_connection(tool_id)
    _exec(
        """
        INSERT INTO tool_connections
          (tool_id, enabled, base_url, auth_type, plan_tier, credential_ciphertext, credential_iv, credential_tag, enabled_capabilities, allowed_agents, connected_by, connected_at, updated_at)
        VALUES (?,1,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(tool_id) DO UPDATE SET
          enabled=1, base_url=excluded.base_url, auth_type=excluded.auth_type, plan_tier=excluded.plan_tier,
          credential_ciphertext=excluded.credential_ciphertext, credential_iv=excluded.credential_iv, credential_tag=excluded.credential_tag,
          enabled_capabilities=excluded.enabled_capabilities, connected_by=excluded.connected_by, connected_at=excluded.connected_at, updated_at=excluded.updated_at
        """,
        (
            tool_id, base_url, auth_type, plan_tier, credential_ciphertext, credential_iv, credential_tag,
            json.dumps(enabled_capabilities), json.dumps(existing.allowedAgents if existing else []),
            connected_by, now, now,
        ),
    )
    return get_tool_connection(tool_id)  # type: ignore[return-value]


def set_tool_enabled(tool_id: str, enabled: bool) -> None:
    now = _iso_now()
    _exec(
        """
        INSERT INTO tool_connections (tool_id, enabled, auth_type, updated_at) VALUES (?,?,'api_key',?)
        ON CONFLICT(tool_id) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at
        """,
        (tool_id, 1 if enabled else 0, now),
    )


def disconnect_tool(tool_id: str) -> None:
    _exec(
        """
        UPDATE tool_connections SET enabled=0, credential_ciphertext=NULL, credential_iv=NULL, credential_tag=NULL,
          connected_by=NULL, connected_at=NULL, last_test_status=NULL, last_test_latency_ms=NULL, last_test_at=NULL, last_error=NULL, updated_at=?
        WHERE tool_id = ?
        """,
        (_iso_now(), tool_id),
    )


def update_tool_permissions(tool_id: str, allowed_agents: list[str], enabled_capabilities: list[str]) -> DbToolConnection:
    now = _iso_now()
    _exec(
        """
        INSERT INTO tool_connections (tool_id, enabled, auth_type, allowed_agents, enabled_capabilities, updated_at) VALUES (?,0,'api_key',?,?,?)
        ON CONFLICT(tool_id) DO UPDATE SET allowed_agents=excluded.allowed_agents, enabled_capabilities=excluded.enabled_capabilities, updated_at=excluded.updated_at
        """,
        (tool_id, json.dumps(allowed_agents), json.dumps(enabled_capabilities), now),
    )
    return get_tool_connection(tool_id)  # type: ignore[return-value]


def record_tool_test_result(tool_id: str, status: str, latency_ms: int, error: Optional[str] = None) -> None:
    now = _iso_now()
    _exec(
        "UPDATE tool_connections SET last_test_status=?, last_test_latency_ms=?, last_test_at=?, last_error=?, updated_at=? WHERE tool_id = ?",
        (status, latency_ms, now, error, now, tool_id),
    )


@dataclass
class DbToolExecutionLog:
    id: str
    toolId: str
    action: str
    requestedBy: str
    requestedByUserId: Optional[str]
    caseId: Optional[str]
    status: str
    latencyMs: int
    verdict: Optional[str]
    error: Optional[str]
    createdAt: str


def _row_to_log(row: sqlite3.Row) -> DbToolExecutionLog:
    return DbToolExecutionLog(
        id=row["id"], toolId=row["tool_id"], action=row["action"], requestedBy=row["requested_by"],
        requestedByUserId=row["requested_by_user_id"], caseId=row["case_id"], status=row["status"],
        latencyMs=row["latency_ms"], verdict=row["verdict"], error=row["error"], createdAt=row["created_at"],
    )


def insert_tool_execution_log(
    tool_id: str, action: str, requested_by: str, requested_by_user_id: Optional[str],
    case_id: Optional[str], status: str, latency_ms: int, verdict: Optional[str], error: Optional[str],
) -> DbToolExecutionLog:
    log_id = f"log-{int(time.time() * 1000)}-{''.join(random.choices(string.ascii_lowercase + string.digits, k=6))}"
    created_at = _iso_now()
    _exec(
        """
        INSERT INTO tool_execution_logs (id, tool_id, action, requested_by, requested_by_user_id, case_id, status, latency_ms, verdict, error, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,
        (log_id, tool_id, action, requested_by, requested_by_user_id, case_id, status, latency_ms, verdict, error, created_at),
    )
    return DbToolExecutionLog(
        id=log_id, toolId=tool_id, action=action, requestedBy=requested_by, requestedByUserId=requested_by_user_id,
        caseId=case_id, status=status, latencyMs=latency_ms, verdict=verdict, error=error, createdAt=created_at,
    )


def list_tool_execution_logs(tool_id: Optional[str] = None, case_id: Optional[str] = None, limit: Optional[int] = None) -> list[DbToolExecutionLog]:
    limit = min(max(limit or 50, 1), 200)
    clauses = []
    params: list[Any] = []
    if tool_id:
        clauses.append("tool_id = ?")
        params.append(tool_id)
    if case_id:
        clauses.append("case_id = ?")
        params.append(case_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    rows = _query_all(f"SELECT * FROM tool_execution_logs {where} ORDER BY created_at DESC LIMIT ?", tuple(params))
    return [_row_to_log(r) for r in rows]


# ---------------------------------------------------------------------------
# Malware Intelligence Engine — samples, rules, reports, IOCs, datasets,
# model registry. See app/malware_intel/ for the extraction/scoring logic
# that produces the values persisted here.
# ---------------------------------------------------------------------------

def _new_id(prefix: str) -> str:
    return f"{prefix}-{int(time.time() * 1000)}-{''.join(random.choices(string.ascii_lowercase + string.digits, k=6))}"


@dataclass
class DbMalwareSample:
    id: str
    name: str
    sha256: str
    sha1: str
    md5: str
    sizeBytes: int
    fileFormat: str
    features: dict
    vector: list
    label: Optional[str]
    family: Optional[str]
    verdict: Optional[str]
    confidence: Optional[float]
    verdictDetail: Optional[dict]
    uploadedBy: str
    caseId: Optional[str]
    createdAt: str
    updatedAt: str


def _row_to_malware_sample(row: sqlite3.Row) -> DbMalwareSample:
    return DbMalwareSample(
        id=row["id"], name=row["name"], sha256=row["sha256"], sha1=row["sha1"], md5=row["md5"],
        sizeBytes=row["size_bytes"], fileFormat=row["file_format"],
        features=json.loads(row["features_json"]), vector=json.loads(row["vector_json"]),
        label=row["label"], family=row["family"], verdict=row["verdict"], confidence=row["confidence"],
        verdictDetail=json.loads(row["verdict_json"]) if row["verdict_json"] else None,
        uploadedBy=row["uploaded_by"], caseId=row["case_id"], createdAt=row["created_at"], updatedAt=row["updated_at"],
    )


def find_malware_sample_by_sha256(sha256: str) -> Optional[DbMalwareSample]:
    row = _query_one("SELECT * FROM malware_samples WHERE sha256 = ?", (sha256.lower(),))
    return _row_to_malware_sample(row) if row else None


def get_malware_sample(sample_id: str) -> Optional[DbMalwareSample]:
    row = _query_one("SELECT * FROM malware_samples WHERE id = ?", (sample_id,))
    return _row_to_malware_sample(row) if row else None


def insert_malware_sample(
    name: str, features: dict, vector: list, uploaded_by: str,
    case_id: Optional[str], label: Optional[str], family: Optional[str],
) -> DbMalwareSample:
    sample_id = _new_id("sample")
    now = _iso_now()
    _exec(
        """
        INSERT INTO malware_samples
          (id, name, sha256, sha1, md5, size_bytes, file_format, features_json, vector_json,
           label, family, verdict, confidence, verdict_json, uploaded_by, case_id, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,?,?,?,?)
        """,
        (
            sample_id, name, features["sha256"].lower(), features["sha1"].lower(), features["md5"].lower(),
            features["sizeBytes"], features["fileFormat"], json.dumps(features), json.dumps(vector),
            label, family, uploaded_by, case_id, now, now,
        ),
    )
    return get_malware_sample(sample_id)  # type: ignore[return-value]


def update_malware_sample_verdict(sample_id: str, verdict: str, confidence: float, verdict_detail: dict) -> None:
    _exec(
        "UPDATE malware_samples SET verdict=?, confidence=?, verdict_json=?, updated_at=? WHERE id=?",
        (verdict, confidence, json.dumps(verdict_detail), _iso_now(), sample_id),
    )


def set_malware_sample_label(sample_id: str, label: Optional[str], family: Optional[str]) -> None:
    _exec(
        "UPDATE malware_samples SET label=?, family=?, updated_at=? WHERE id=?",
        (label, family, _iso_now(), sample_id),
    )


def list_malware_samples(limit: int = 100) -> list[DbMalwareSample]:
    limit = min(max(limit, 1), 500)
    rows = _query_all("SELECT * FROM malware_samples ORDER BY created_at DESC LIMIT ?", (limit,))
    return [_row_to_malware_sample(r) for r in rows]


def list_malware_similarity_corpus(exclude_sample_id: Optional[str] = None) -> list[dict]:
    """Lightweight projection used by the similarity engine — id/name/family/label/vector only."""
    rows = _query_all("SELECT id, name, family, label, vector_json FROM malware_samples")
    corpus = []
    for r in rows:
        if exclude_sample_id and r["id"] == exclude_sample_id:
            continue
        corpus.append({
            "id": r["id"], "name": r["name"], "family": r["family"], "label": r["label"],
            "vector": json.loads(r["vector_json"]),
        })
    return corpus


def malware_sample_counts() -> dict:
    row = _query_one(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN label='malicious' THEN 1 ELSE 0 END) AS malicious,
               SUM(CASE WHEN label='benign' THEN 1 ELSE 0 END) AS benign,
               COUNT(DISTINCT family) AS families
        FROM malware_samples
        """
    )
    return {
        "total": row["total"] or 0,
        "malicious": row["malicious"] or 0,
        "benign": row["benign"] or 0,
        "families": row["families"] or 0,
    }


# --- Rules -------------------------------------------------------------

def insert_malware_rule(name: str, kind: str, pattern: str, family: Optional[str], severity: str, source: Optional[str], created_by: str, agent_id: str = "malware-analysis") -> dict:
    rule_id = _new_id("rule")
    now = _iso_now()
    _exec(
        "INSERT INTO malware_rules (id,name,kind,pattern,family,severity,source,created_by,agent_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (rule_id, name, kind, pattern, family, severity, source, created_by, agent_id, now),
    )
    return dict(id=rule_id, name=name, kind=kind, pattern=pattern, family=family, severity=severity, source=source, createdBy=created_by, agentId=agent_id, createdAt=now)


def list_malware_rules(agent_id: Optional[str] = None) -> list[dict]:
    if agent_id:
        rows = _query_all("SELECT * FROM malware_rules WHERE agent_id = ? ORDER BY created_at DESC", (agent_id,))
    else:
        rows = _query_all("SELECT * FROM malware_rules ORDER BY created_at DESC")
    return [
        dict(id=r["id"], name=r["name"], kind=r["kind"], pattern=r["pattern"], family=r["family"],
             severity=r["severity"], source=r["source"], createdBy=r["created_by"],
             agentId=r["agent_id"], createdAt=r["created_at"])
        for r in rows
    ]


def delete_malware_rule(rule_id: str) -> bool:
    cur = _exec("DELETE FROM malware_rules WHERE id = ?", (rule_id,))
    return cur.rowcount > 0


# --- Reports / Knowledge base -------------------------------------------

def insert_malware_report(name: str, content_excerpt: str, extracted_iocs: dict, extracted_families: list, uploaded_by: str) -> dict:
    report_id = _new_id("report")
    now = _iso_now()
    _exec(
        "INSERT INTO malware_reports (id,name,content_excerpt,extracted_iocs_json,extracted_families_json,uploaded_by,created_at) VALUES (?,?,?,?,?,?,?)",
        (report_id, name, content_excerpt, json.dumps(extracted_iocs), json.dumps(extracted_families), uploaded_by, now),
    )
    return dict(id=report_id, name=name, contentExcerpt=content_excerpt, extractedIOCs=extracted_iocs,
                extractedFamilies=extracted_families, uploadedBy=uploaded_by, createdAt=now)


def list_malware_reports(limit: int = 50) -> list[dict]:
    rows = _query_all("SELECT * FROM malware_reports ORDER BY created_at DESC LIMIT ?", (min(max(limit, 1), 200),))
    return [
        dict(id=r["id"], name=r["name"], contentExcerpt=r["content_excerpt"],
             extractedIOCs=json.loads(r["extracted_iocs_json"]), extractedFamilies=json.loads(r["extracted_families_json"]),
             uploadedBy=r["uploaded_by"], createdAt=r["created_at"])
        for r in rows
    ]


def upsert_malware_iocs(iocs: list[tuple[str, str]], family: Optional[str], source_report_id: Optional[str], source_sample_id: Optional[str]) -> int:
    """`iocs` is a list of (type, value). Returns count of newly inserted (non-duplicate) IOCs."""
    inserted = 0
    now = _iso_now()
    for ioc_type, value in iocs:
        ioc_id = _new_id("ioc")
        try:
            _exec(
                "INSERT INTO malware_iocs (id,type,value,family,source_report_id,source_sample_id,created_at) VALUES (?,?,?,?,?,?,?)",
                (ioc_id, ioc_type, value, family, source_report_id, source_sample_id, now),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            continue  # already catalogued
    return inserted


def list_malware_iocs(ioc_type: Optional[str] = None, limit: int = 200) -> list[dict]:
    limit = min(max(limit, 1), 1000)
    if ioc_type:
        rows = _query_all("SELECT * FROM malware_iocs WHERE type = ? ORDER BY created_at DESC LIMIT ?", (ioc_type, limit))
    else:
        rows = _query_all("SELECT * FROM malware_iocs ORDER BY created_at DESC LIMIT ?", (limit,))
    return [
        dict(id=r["id"], type=r["type"], value=r["value"], family=r["family"],
             sourceReportId=r["source_report_id"], sourceSampleId=r["source_sample_id"], createdAt=r["created_at"])
        for r in rows
    ]


def malware_family_summary() -> list[dict]:
    rows = _query_all(
        """
        SELECT family, COUNT(*) AS sample_count
        FROM malware_samples
        WHERE family IS NOT NULL AND family != ''
        GROUP BY family
        ORDER BY sample_count DESC
        """
    )
    result = []
    for r in rows:
        ioc_row = _query_one("SELECT COUNT(*) AS c FROM malware_iocs WHERE family = ?", (r["family"],))
        result.append({"family": r["family"], "sampleCount": r["sample_count"], "iocCount": ioc_row["c"] if ioc_row else 0})
    return result


# --- Datasets -------------------------------------------------------------

def find_malware_dataset_by_hash(content_hash: str) -> Optional[dict]:
    row = _query_one("SELECT * FROM malware_datasets WHERE content_hash = ?", (content_hash,))
    if not row:
        return None
    return dict(id=row["id"], name=row["name"], contentHash=row["content_hash"], datasetType=row["dataset_type"],
                numRows=row["num_rows"], numMalicious=row["num_malicious"], numBenign=row["num_benign"],
                numReference=row["num_reference"], uploadedBy=row["uploaded_by"], createdAt=row["created_at"])


def insert_malware_dataset(name: str, content_hash: str, rows: list[dict], uploaded_by: str, dataset_type: str = "malware_training") -> dict:
    dataset_id = _new_id("dataset")
    now = _iso_now()
    num_malicious = sum(1 for r in rows if r["label"] == "malicious")
    num_benign = sum(1 for r in rows if r["label"] == "benign")
    num_reference = sum(1 for r in rows if r["label"] is None)
    _exec(
        "INSERT INTO malware_datasets (id,name,content_hash,dataset_type,num_rows,num_malicious,num_benign,num_reference,uploaded_by,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (dataset_id, name, content_hash, dataset_type, len(rows), num_malicious, num_benign, num_reference, uploaded_by, now),
    )
    row_params = []
    for row in rows:
        row_id = _new_id("drow")
        vector_json = json.dumps(row["vector"]) if row.get("vector") is not None else None
        raw_json = json.dumps(row["raw"], default=str) if row.get("raw") is not None else None
        row_params.append((row_id, dataset_id, row.get("sampleRef"), row["label"], row.get("family"), vector_json, row.get("vectorSource"), raw_json, now))
    try:
        _exec_many(
            "INSERT INTO malware_dataset_rows (id,dataset_id,sample_ref,label,family,vector_json,vector_source,raw_json,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            row_params,
        )
    except sqlite3.IntegrityError as err:
        # Defensive self-heal: if the table somehow still has the old strict
        # (pre-migration) schema — e.g. a DB file created by a very old build —
        # rebuild it once and retry, instead of surfacing a raw DB error for
        # what is really just a stale schema on disk.
        safe_logger.warn("malware_dataset_rows insert hit a constraint — re-running schema migration and retrying once.", {"error": str(err)})
        _migrate_malware_dataset_rows_schema()
        _exec_many(
            "INSERT INTO malware_dataset_rows (id,dataset_id,sample_ref,label,family,vector_json,vector_source,raw_json,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            row_params,
        )
    return dict(id=dataset_id, name=name, contentHash=content_hash, datasetType=dataset_type, numRows=len(rows),
                numMalicious=num_malicious, numBenign=num_benign, numReference=num_reference, uploadedBy=uploaded_by, createdAt=now)


def list_malware_datasets() -> list[dict]:
    rows = _query_all("SELECT * FROM malware_datasets ORDER BY created_at DESC")
    return [
        dict(id=r["id"], name=r["name"], contentHash=r["content_hash"], datasetType=r["dataset_type"], numRows=r["num_rows"],
             numMalicious=r["num_malicious"], numBenign=r["num_benign"], numReference=r["num_reference"],
             uploadedBy=r["uploaded_by"], createdAt=r["created_at"])
        for r in rows
    ]


def list_all_labeled_vectors() -> list[tuple[list[float], int]]:
    """Combines confirmed sample labels + labeled, vectorized dataset rows into one training set.
    Reference rows (no recognizable label and/or no derivable feature vector) are stored for
    other agents/knowledge use but are never fed to the classifier."""
    samples: list[tuple[list[float], int]] = []
    for r in _query_all("SELECT vector_json, label FROM malware_samples WHERE label IS NOT NULL"):
        samples.append((json.loads(r["vector_json"]), 1 if r["label"] == "malicious" else 0))
    for r in _query_all("SELECT vector_json, label FROM malware_dataset_rows WHERE label IS NOT NULL AND vector_json IS NOT NULL"):
        samples.append((json.loads(r["vector_json"]), 1 if r["label"] == "malicious" else 0))
    return samples


def list_malware_dataset_rows(dataset_id: str, limit: int = 200) -> list[dict]:
    """Row-level access so other agents (IOC, threat intel, etc.) can pull whatever a dataset
    actually contains, not just the rows that were usable for classifier training."""
    limit = min(max(limit, 1), 2000)
    rows = _query_all(
        "SELECT * FROM malware_dataset_rows WHERE dataset_id = ? ORDER BY created_at ASC LIMIT ?",
        (dataset_id, limit),
    )
    return [
        dict(
            id=r["id"], sampleRef=r["sample_ref"], label=r["label"], family=r["family"],
            vector=json.loads(r["vector_json"]) if r["vector_json"] else None,
            vectorSource=r["vector_source"],
            raw=json.loads(r["raw_json"]) if r["raw_json"] else None,
            createdAt=r["created_at"],
        )
        for r in rows
    ]


# --- Model registry ---------------------------------------------------

def insert_malware_model_version(weights: list[float], bias: float, train_accuracy: float, num_samples: int, num_malicious: int, num_benign: int, trained_by: str) -> dict:
    latest = _query_one("SELECT MAX(version) AS v FROM malware_model_versions")
    next_version = (latest["v"] or 0) + 1
    model_id = _new_id("model")
    now = _iso_now()
    _exec(
        """
        INSERT INTO malware_model_versions
          (id, version, weights_json, bias, train_accuracy, num_samples, num_malicious, num_benign, trained_by, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (model_id, next_version, json.dumps(weights), bias, train_accuracy, num_samples, num_malicious, num_benign, trained_by, now),
    )
    return dict(id=model_id, version=next_version, weights=weights, bias=bias, trainAccuracy=train_accuracy,
                numSamples=num_samples, numMalicious=num_malicious, numBenign=num_benign, trainedBy=trained_by, createdAt=now)


def get_latest_malware_model() -> Optional[dict]:
    row = _query_one("SELECT * FROM malware_model_versions ORDER BY version DESC LIMIT 1")
    if not row:
        return None
    return dict(id=row["id"], version=row["version"], weights=json.loads(row["weights_json"]), bias=row["bias"],
                trainAccuracy=row["train_accuracy"], numSamples=row["num_samples"], numMalicious=row["num_malicious"],
                numBenign=row["num_benign"], trainedBy=row["trained_by"], createdAt=row["created_at"])


def list_malware_model_versions() -> list[dict]:
    rows = _query_all("SELECT * FROM malware_model_versions ORDER BY version DESC")
    return [
        dict(id=r["id"], version=r["version"], bias=r["bias"], trainAccuracy=r["train_accuracy"],
             numSamples=r["num_samples"], numMalicious=r["num_malicious"], numBenign=r["num_benign"],
             trainedBy=r["trained_by"], createdAt=r["created_at"])
        for r in rows
    ]
