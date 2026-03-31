"""Create scan_records table.

Revision ID: 002
Revises: 001
Create Date: 2024-01-01 00:01:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_records",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("scan_type", sa.String(length=20), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column(
            "total_entities",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("recommended_action", sa.String(length=10), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("entities_json", sa.Text(), nullable=False),
        sa.Column("input_preview", sa.String(length=200), nullable=True),
        sa.Column("filename", sa.String(length=255), nullable=True),
        sa.Column("source_ip", sa.String(length=50), nullable=True),
        sa.Column("scan_duration_ms", sa.Float(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", name="uq_scan_records_scan_id"),
    )
    # Index on scan_id for fast lookups
    op.create_index("ix_scan_records_scan_id", "scan_records", ["scan_id"], unique=True)
    # Index on tenant_id for fast per-tenant queries
    op.create_index("ix_scan_records_tenant_id", "scan_records", ["tenant_id"], unique=False)
    # Composite index on (tenant_id, created_at) for chronological tenant history
    op.create_index(
        "ix_scan_records_tenant_created",
        "scan_records",
        ["tenant_id", "created_at"],
        unique=False,
    )
    # Composite index on (tenant_id, severity) for filtered tenant queries
    op.create_index(
        "ix_scan_records_tenant_severity",
        "scan_records",
        ["tenant_id", "severity"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_scan_records_tenant_severity", table_name="scan_records")
    op.drop_index("ix_scan_records_tenant_created", table_name="scan_records")
    op.drop_index("ix_scan_records_tenant_id", table_name="scan_records")
    op.drop_index("ix_scan_records_scan_id", table_name="scan_records")
    op.drop_table("scan_records")
