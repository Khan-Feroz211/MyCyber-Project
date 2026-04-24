"""Add scheduled_scans table.

Revision ID: 007
Revises: 006
Create Date: 2026-04-24 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "scheduled_scans" not in inspector.get_table_names():
        op.create_table(
            "scheduled_scans",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("job_id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("scan_type", sa.String(length=20), nullable=False),
            sa.Column("target", sa.Text(), nullable=False),
            sa.Column("schedule_cron", sa.String(length=50), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("job_id"),
        )
        op.create_index("ix_scheduled_scans_tenant_id", "scheduled_scans", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_scheduled_scans_tenant_id", table_name="scheduled_scans")
    op.drop_table("scheduled_scans")
