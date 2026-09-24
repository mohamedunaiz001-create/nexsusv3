"""Phase 5: mission-specific cybersecurity scoring weights.

Every mission seeded in 0003_phase5_playground_battle used the exact
same generic weight set (accuracy/depth/actionability/evidence/speed),
which meant the Battle Judge's weighting profile never actually
reflected what matters for a given mission type, and never touched
ioc_precision/ioc_recall/mitre_accuracy/detection_accuracy/
recommendation_quality even though the judge computes all of them.

This replaces each mission's `scoring_weights` with a profile built
from the nine dimensions agents/battle/judge.py actually scores,
weighted by what actually matters for that kind of analysis (e.g.
MITRE mapping matters far more for malware/threat-intel than for a
code review; IOC recall matters more for log/network investigation
than for phishing). Every profile still sums to 1.0.

Revision ID: 0005_phase5_cyber_scoring_weights
Revises: 0004_phase5_evidence_user_optional
"""
import json

from alembic import op
import sqlalchemy as sa

revision = "0005_phase5_cyber_scoring_weights"
down_revision = "0004_phase5_evidence_user_optional"
branch_labels = None
depends_on = None

# dims: detection_accuracy, ioc_precision, ioc_recall, mitre_accuracy,
#       evidence, depth, recommendation_quality, speed — each sums to 1.0
_WEIGHTS = {
    "malware_analysis": {
        "detection_accuracy": 0.25,
        "ioc_precision": 0.10,
        "ioc_recall": 0.15,
        "mitre_accuracy": 0.15,
        "evidence": 0.15,
        "depth": 0.10,
        "recommendation_quality": 0.05,
        "speed": 0.05,
    },
    "phishing_analysis": {
        "detection_accuracy": 0.25,
        "ioc_precision": 0.15,
        "ioc_recall": 0.15,
        "mitre_accuracy": 0.05,
        "evidence": 0.15,
        "depth": 0.10,
        "recommendation_quality": 0.10,
        "speed": 0.05,
    },
    "log_investigation": {
        "detection_accuracy": 0.25,
        "ioc_precision": 0.10,
        "ioc_recall": 0.20,
        "mitre_accuracy": 0.15,
        "evidence": 0.15,
        "depth": 0.05,
        "recommendation_quality": 0.05,
        "speed": 0.05,
    },
    "code_review": {
        "detection_accuracy": 0.30,
        "ioc_precision": 0.05,
        "ioc_recall": 0.05,
        "mitre_accuracy": 0.05,
        "evidence": 0.20,
        "depth": 0.15,
        "recommendation_quality": 0.15,
        "speed": 0.05,
    },
    "threat_intel": {
        "detection_accuracy": 0.20,
        "ioc_precision": 0.15,
        "ioc_recall": 0.15,
        "mitre_accuracy": 0.20,
        "evidence": 0.15,
        "depth": 0.10,
        "recommendation_quality": 0.03,
        "speed": 0.02,
    },
    "network_analysis": {
        "detection_accuracy": 0.25,
        "ioc_precision": 0.15,
        "ioc_recall": 0.15,
        "mitre_accuracy": 0.10,
        "evidence": 0.15,
        "depth": 0.10,
        "recommendation_quality": 0.05,
        "speed": 0.05,
    },
}

_OLD_GENERIC_WEIGHTS = {
    "accuracy": 0.30,
    "depth": 0.25,
    "actionability": 0.20,
    "evidence": 0.15,
    "speed": 0.10,
}

battle_missions = sa.table(
    "battle_missions",
    sa.column("mission_type", sa.String),
    sa.column("scoring_weights", sa.JSON),
)


def upgrade() -> None:
    for mission_type, weights in _WEIGHTS.items():
        op.execute(
            battle_missions.update()
            .where(battle_missions.c.mission_type == mission_type)
            .values(scoring_weights=json.dumps(weights))
        )


def downgrade() -> None:
    for mission_type in _WEIGHTS:
        op.execute(
            battle_missions.update()
            .where(battle_missions.c.mission_type == mission_type)
            .values(scoring_weights=json.dumps(_OLD_GENERIC_WEIGHTS))
        )
