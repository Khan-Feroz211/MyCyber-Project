"""add alert review status

Revision ID: 008
Revises: 007
Create Date: 2026-04-27

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '008'
down_revision: Union[str, None] = '007'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = '007'


def upgrade() -> None:
    # Add review_status column with default 'pending'
    op.add_column('alerts', sa.Column('review_status', sa.String(20), nullable=False, server_default='pending'))
    
    # Add reviewed_at column
    op.add_column('alerts', sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    # Remove columns in reverse order
    op.drop_column('alerts', 'reviewed_at')
    op.drop_column('alerts', 'review_status')
