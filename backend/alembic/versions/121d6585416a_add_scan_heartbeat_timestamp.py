"""add scan heartbeat timestamp

Revision ID: 121d6585416a
Revises: aa4d71ba155a
Create Date: 2026-10-26 21:42:34.905948

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '121d6585416a'
down_revision: Union[str, Sequence[str], None] = 'aa4d71ba155a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "last_heartbeat_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "last_heartbeat_at")