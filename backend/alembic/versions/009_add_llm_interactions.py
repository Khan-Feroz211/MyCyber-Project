"""add llm interactions table

Revision ID: 009
Revises: 008
Create Date: 2026-04-27

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '009'
down_revision: Union[str, None] = '008'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = '008'


def upgrade() -> None:
    op.create_table(
        'llm_interactions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('interaction_id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('tenant_id', sa.String(36), nullable=False),
        sa.Column('original_prompt', sa.Text(), nullable=False),
        sa.Column('redacted_prompt', sa.Text(), nullable=True),
        sa.Column('llm_response', sa.Text(), nullable=True),
        sa.Column('post_scan_summary', sa.Text(), nullable=True),
        sa.Column('pre_entities_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('post_entities_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('exposed_keys_json', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('auto_deactivated', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('status', sa.String(20), nullable=False, server_default='allowed'),
        sa.Column('llm_provider', sa.String(50), nullable=True),
        sa.Column('model_used', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('interaction_id'),
    )
    op.create_index('ix_llm_interactions_tenant_id', 'llm_interactions', ['tenant_id'])
    op.create_index('ix_llm_interactions_status', 'llm_interactions', ['status'])
    op.create_index('ix_llm_interactions_created_at', 'llm_interactions', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_llm_interactions_created_at', table_name='llm_interactions')
    op.drop_index('ix_llm_interactions_status', table_name='llm_interactions')
    op.drop_index('ix_llm_interactions_tenant_id', table_name='llm_interactions')
    op.drop_table('llm_interactions')
