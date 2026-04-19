"""Add MFA/lockout fields and security_audit_events table.

Revision ID: 006
Revises: 005
Create Date: 2026-01-13 00:00:00.000000
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    user_columns = {column["name"] for column in inspector.get_columns("users")}
    if "mfa_enabled" not in user_columns:
        op.add_column(
            "users",
            sa.Column(
                "mfa_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
        )
    if "mfa_secret" not in user_columns:
        op.add_column("users", sa.Column("mfa_secret", sa.String(length=64), nullable=True))
    if "failed_login_attempts" not in user_columns:
        op.add_column(
            "users",
            sa.Column(
                "failed_login_attempts",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            ),
        )
    if "locked_until" not in user_columns:
        op.add_column(
            "users",
            sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        )
    if "last_login_ip" not in user_columns:
        op.add_column("users", sa.Column("last_login_ip", sa.String(length=64), nullable=True))

    if "security_audit_events" not in inspector.get_table_names():
        op.create_table(
            "security_audit_events",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("event_id", sa.String(length=36), nullable=False),
            sa.Column(
                "user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("tenant_id", sa.String(length=36), nullable=True),
            sa.Column("event_type", sa.String(length=64), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default="INFO"),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("user_agent", sa.String(length=255), nullable=True),
            sa.Column("details_json", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("event_id"),
        )

    inspector = sa.inspect(bind)
    if "security_audit_events" in inspector.get_table_names():
        existing_indexes = {index["name"] for index in inspector.get_indexes("security_audit_events")}
        if "ix_security_audit_events_tenant_id" not in existing_indexes:
            op.create_index(
                "ix_security_audit_events_tenant_id",
                "security_audit_events",
                ["tenant_id"],
                unique=False,
            )
        if "ix_security_audit_events_event_type" not in existing_indexes:
            op.create_index(
                "ix_security_audit_events_event_type",
                "security_audit_events",
                ["event_type"],
                unique=False,
            )
        if "ix_security_audit_events_severity" not in existing_indexes:
            op.create_index(
                "ix_security_audit_events_severity",
                "security_audit_events",
                ["severity"],
                unique=False,
            )


def downgrade() -> None:
    op.drop_index("ix_security_audit_events_severity", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_event_type", table_name="security_audit_events")
    op.drop_index("ix_security_audit_events_tenant_id", table_name="security_audit_events")
    op.drop_table("security_audit_events")

    op.drop_column("users", "last_login_ip")
    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_attempts")
    op.drop_column("users", "mfa_secret")
    op.drop_column("users", "mfa_enabled")
