"""Create subscriptions table.

Revision ID: 004
Revises: 003
Create Date: 2024-01-01 00:03:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "subscriptions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("sub_id", sa.String(36), nullable=False),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("plan", sa.String(20), nullable=False),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="active",
        ),
        sa.Column("scan_limit", sa.Integer(), nullable=False),
        sa.Column("price_pkr", sa.Integer(), nullable=False),
        sa.Column(
            "billing_cycle",
            sa.String(20),
            server_default="monthly",
        ),
        sa.Column(
            "current_period_start",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "current_period_end",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("safepay_token", sa.String(255), nullable=True),
        sa.Column("safepay_tracker", sa.String(255), nullable=True),
        sa.Column(
            "cancelled_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sub_id"),
    )
    op.create_index(
        "ix_subscriptions_tenant_id",
        "subscriptions",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_subscriptions_user_id",
        "subscriptions",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_subscriptions_user_id", table_name="subscriptions")
    op.drop_index("ix_subscriptions_tenant_id", table_name="subscriptions")
    op.drop_table("subscriptions")
