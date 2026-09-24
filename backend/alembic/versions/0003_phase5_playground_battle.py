"""Phase 5: Playground and Battle tables

Adds playground_sessions, playground_responses, battle_sessions, battle_scores, battle_missions.

Revision ID: 0003_phase5_playground_battle
Revises: 0002_provider_hub
Create Date: 2026-08-09
"""
import uuid

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0003_phase5_playground_battle"
down_revision = "0002_provider_hub"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Playground tables ---
    op.create_table(
        "playground_sessions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("prompt", sa.Text(), nullable=False),
        sa.Column("model_configs", sa.JSON(), nullable=False),
        sa.Column("temperature", sa.Float(), server_default="0.7"),
        sa.Column("max_tokens", sa.Integer(), server_default="2000"),
        sa.Column("file_ids", sa.JSON(), server_default="[]"),
        sa.Column("status", sa.String(20), server_default="created"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "playground_responses",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("playground_sessions.id"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("model", sa.String(150), nullable=False),
        sa.Column("content", sa.Text(), server_default=""),
        sa.Column("structured", sa.JSON(), nullable=True),
        sa.Column("tokens_prompt", sa.Integer(), nullable=True),
        sa.Column("tokens_completion", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("estimated_cost_usd", sa.Float(), nullable=True),
        sa.Column("status", sa.String(20), server_default="streaming"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # --- Battle tables ---
    op.create_table(
        "battle_sessions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("mission_type", sa.String(50), nullable=False),
        sa.Column("task_description", sa.Text(), nullable=False),
        sa.Column("file_ids", sa.JSON(), server_default="[]"),
        sa.Column("model_configs", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(20), server_default="created"),
        sa.Column("winner_model", sa.String(200), nullable=True),
        sa.Column("winner_score", sa.Float(), nullable=True),
        sa.Column("judge_reasoning", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "battle_responses",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("battle_id", UUID(as_uuid=True), sa.ForeignKey("battle_sessions.id"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("model", sa.String(150), nullable=False),
        sa.Column("content", sa.Text(), server_default=""),
        sa.Column("structured", sa.JSON(), nullable=True),
        sa.Column("tokens_prompt", sa.Integer(), nullable=True),
        sa.Column("tokens_completion", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("estimated_cost_usd", sa.Float(), nullable=True),
        sa.Column("status", sa.String(20), server_default="streaming"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "battle_scores",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("battle_id", UUID(as_uuid=True), sa.ForeignKey("battle_sessions.id"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("model", sa.String(150), nullable=False),
        sa.Column("accuracy", sa.Float(), nullable=True),
        sa.Column("depth", sa.Float(), nullable=True),
        sa.Column("actionability", sa.Float(), nullable=True),
        sa.Column("evidence", sa.Float(), nullable=True),
        sa.Column("speed", sa.Float(), nullable=True),
        sa.Column("total_score", sa.Float(), nullable=True),
        sa.Column("ioc_precision", sa.Float(), nullable=True),
        sa.Column("ioc_recall", sa.Float(), nullable=True),
        sa.Column("mitre_accuracy", sa.Float(), nullable=True),
        sa.Column("detection_accuracy", sa.Float(), nullable=True),
        sa.Column("recommendation_quality", sa.Float(), nullable=True),
        sa.Column("judge_reasoning", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "battle_missions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("mission_type", sa.String(50), nullable=False),
        sa.Column("system_prompt", sa.Text(), nullable=False),
        sa.Column("scoring_weights", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Insert default missions
    op.execute("""
        INSERT INTO battle_missions (id, name, description, mission_type, system_prompt, scoring_weights, is_active, created_at, updated_at)
        VALUES 
        (gen_random_uuid(), 'Malware Analysis', 'Analyze suspicious file behavior, extract IOCs, map MITRE techniques', 'malware_analysis', 
         'You are a senior malware analyst. Analyze the provided sample/artifact and produce a comprehensive report covering: 1) File type and basic properties 2) Suspicious behaviors and indicators 3) Extracted IOCs (IPs, domains, hashes, etc.) 4) MITRE ATT&CK technique mapping 5) Persistence mechanisms 6) Threat classification and confidence 7) Recommendations for detection and mitigation. Be specific, cite evidence, and prioritize actionable findings.',
         '{"accuracy": 0.30, "depth": 0.25, "actionability": 0.20, "evidence": 0.15, "speed": 0.10}', true, now(), now()),
        (gen_random_uuid(), 'Phishing Analysis', 'Analyze email sender, URLs, headers, social engineering tactics', 'phishing_analysis',
         'You are a senior phishing analyst. Analyze the provided email/message and produce a comprehensive report covering: 1) Sender analysis (domain, SPF/DKIM/DMARC) 2) URL analysis (redirects, reputation, phishing kits) 3) Header analysis (routing, authentication) 4) Social engineering tactics used 5) Malicious indicators 6) Risk scoring 7) Recommendations for user education and blocking.',
         '{"accuracy": 0.30, "depth": 0.25, "actionability": 0.20, "evidence": 0.15, "speed": 0.10}', true, now(), now()),
        (gen_random_uuid(), 'Log Investigation', 'Find suspicious IPs, authentication anomalies, attack patterns in logs', 'log_investigation',
         'You are a senior SOC analyst. Analyze the provided logs and produce a comprehensive report covering: 1) Timeline of events 2) Suspicious IPs and their reputation 3) Authentication anomalies (failed logins, impossible travel, etc.) 4) Attack patterns (brute force, credential stuffing, etc.) 5) Extracted IOCs 6) MITRE ATT&CK mapping 7) Recommended containment and investigation steps.',
         '{"accuracy": 0.30, "depth": 0.25, "actionability": 0.20, "evidence": 0.15, "speed": 0.10}', true, now(), now()),
        (gen_random_uuid(), 'Code Security Review', 'Find OWASP vulnerabilities, injection flaws, auth issues, secrets', 'code_review',
         'You are a senior application security engineer. Review the provided code and produce a comprehensive report covering: 1) OWASP Top 10 vulnerabilities found 2) Injection flaws (SQL, command, LDAP, etc.) 3) Authentication and authorization issues 4) Hardcoded secrets and sensitive data exposure 5) Insecure dependencies and outdated libraries 6) Secure coding practice violations 7) Risk ratings and remediation priorities with code examples.',
         '{"accuracy": 0.30, "depth": 0.25, "actionability": 0.20, "evidence": 0.15, "speed": 0.10}', true, now(), now()),
        (gen_random_uuid(), 'Threat Intelligence', 'Analyze threat actor, campaign, TTPs, IOCs, MITRE techniques', 'threat_intel',
         'You are a senior threat intelligence analyst. Analyze the provided threat data and produce a comprehensive report covering: 1) Threat actor/campaign identification 2) TTPs and MITRE ATT&CK mapping 3) Associated IOCs with confidence 4) Infrastructure analysis 5) Victimology and targeting 6) Attribution confidence 7) Defensive recommendations and detection rules.',
         '{"accuracy": 0.30, "depth": 0.25, "actionability": 0.20, "evidence": 0.15, "speed": 0.10}', true, now(), now()),
        (gen_random_uuid(), 'Network Analysis', 'Analyze connections, protocols, suspicious traffic, DNS, C2 indicators', 'network_analysis',
         'You are a senior network security analyst. Analyze the provided network capture/logs and produce a comprehensive report covering: 1) Connection summary and topology 2) Protocol analysis and anomalies 3) Suspicious traffic patterns 4) DNS analysis (tunneling, DGA, suspicious domains) 5) C2 beaconing indicators 6) Data exfiltration indicators 7) Network-based IOCs and detection rules.',
         '{"accuracy": 0.30, "depth": 0.25, "actionability": 0.20, "evidence": 0.15, "speed": 0.10}', true, now(), now());
    """)


def downgrade() -> None:
    op.drop_table("battle_missions")
    op.drop_table("battle_scores")
    op.drop_table("battle_responses")
    op.drop_table("battle_sessions")
    op.drop_table("playground_responses")
    op.drop_table("playground_sessions")