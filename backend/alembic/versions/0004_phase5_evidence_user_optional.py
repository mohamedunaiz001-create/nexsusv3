"""Allow evidence records not tied to an authenticated user.

Revision ID: 0004_phase5_evidence_user_optional
Revises: 0003_phase5_playground_battle
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_phase5_evidence_user_optional"
down_revision = "0003_phase5_playground_battle"
branch_labels = None
depends_on = None

def upgrade():
    op.alter_column("files", "uploader_id", existing_type=sa.UUID(), nullable=True)

def downgrade():
    op.alter_column("files", "uploader_id", existing_type=sa.UUID(), nullable=False)
