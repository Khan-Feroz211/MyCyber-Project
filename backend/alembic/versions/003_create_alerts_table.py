"""Create alerts table.

Revision ID: 003
Revises: 002
Create Date: 2024-01-01 00:02:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("alert_id", sa.String(length=36), nullable=False),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column(
            "scan_id",
            sa.String(length=36),
            sa.ForeignKey("scan_records.scan_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column(
            "is_acknowledged",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("alert_id", name="uq_alerts_alert_id"),
    )
    # Index on tenant_id for per-tenant queries
    op.create_index("ix_alerts_tenant_id", "alerts", ["tenant_id"], unique=False)
    # Composite index on (tenant_id, is_acknowledged) for unread alert queries
    op.create_index(
        "ix_alerts_tenant_acknowledged",
        "alerts",
        ["tenant_id", "is_acknowledged"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_alerts_tenant_acknowledged", table_name="alerts")
    op.drop_index("ix_alerts_tenant_id", table_name="alerts")
    op.drop_table("alerts")
