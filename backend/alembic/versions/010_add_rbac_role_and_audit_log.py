"""Add RBAC role to users, audit_log_entries table, and encryption key fields.

Revision ID: 010
Revises: 009
Create Date: 2026-07-31

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = "009"


def _table_exists(table_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def _column_exists(table_name: str, column_name: str) -> bool:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    cols = {c["name"] for c in inspector.get_columns(table_name)}
    return column_name in cols


def upgrade() -> None:
    # --- users.role column (RBAC hardening) ---
    if _column_exists("users", "role"):
        pass
    else:
        op.add_column(
            "users",
            sa.Column(
                "role",
                sa.String(length=20),
                nullable=False,
                server_default="viewer",
            ),
        )

    # --- audit_log_entries table (immutable, hash-chained) ---
    if not _table_exists("audit_log_entries"):
        op.create_table(
            "audit_log_entries",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column(
                "entry_id",
                sa.String(length=36),
                nullable=False,
                unique=True,
            ),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column(
                "actor_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("event_type", sa.String(length=64), nullable=False),
            sa.Column("resource_type", sa.String(length=64), nullable=False),
            sa.Column("resource_id", sa.String(length=36), nullable=True),
            sa.Column("action", sa.String(length=32), nullable=False),
            sa.Column(
                "severity",
                sa.String(length=16),
                nullable=False,
                server_default="INFO",
            ),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("user_agent", sa.String(length=255), nullable=True),
            sa.Column("details_json", sa.Text(), nullable=False),
            sa.Column(
                "previous_hash",
                sa.String(length=64),
                nullable=False,
                server_default="GENESIS",
            ),
            sa.Column("entry_hash", sa.String(length=64), nullable=False),
            sa.Column(
                "key_version",
                sa.Integer(),
                nullable=False,
                server_default="1",
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.PrimaryKeyConstraint("id"),
        )

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_indexes = {idx["name"] for idx in inspector.get_indexes("audit_log_entries")}

    if "ix_audit_log_entries_tenant_id" not in existing_indexes:
        op.create_index(
            "ix_audit_log_entries_tenant_id",
            "audit_log_entries",
            ["tenant_id"],
        )
    if "ix_audit_log_entries_actor_id" not in existing_indexes:
        op.create_index(
            "ix_audit_log_entries_actor_id",
            "audit_log_entries",
            ["actor_id"],
        )
    if "ix_audit_log_entries_event_type" not in existing_indexes:
        op.create_index(
            "ix_audit_log_entries_event_type",
            "audit_log_entries",
            ["event_type"],
        )
    if "ix_audit_log_entries_created_at" not in existing_indexes:
        op.create_index(
            "ix_audit_log_entries_created_at",
            "audit_log_entries",
            ["created_at"],
        )
    if "ix_audit_log_entries_entry_hash" not in existing_indexes:
        op.create_index(
            "ix_audit_log_entries_entry_hash",
            "audit_log_entries",
            ["entry_hash"],
        )


def downgrade() -> None:
    op.drop_index("ix_audit_log_entries_entry_hash", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_created_at", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_event_type", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_actor_id", table_name="audit_log_entries")
    op.drop_index("ix_audit_log_entries_tenant_id", table_name="audit_log_entries")
    op.drop_table("audit_log_entries")
    op.drop_column("users", "role")
