"""Add project ownership.

Revision ID: d1728b9adb25
Revises: 663179c0e0f9
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "d1728b9adb25"
down_revision: Union[str, Sequence[str], None] = "663179c0e0f9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("projects", recreate="always") as batch_op:
        batch_op.add_column(
            sa.Column("owner_id", sa.String(length=36), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_projects_owner_id_users",
            "users",
            ["owner_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_index(
            "ix_projects_owner_id",
            ["owner_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("projects", recreate="always") as batch_op:
        batch_op.drop_index("ix_projects_owner_id")
        batch_op.drop_constraint(
            "fk_projects_owner_id_users",
            type_="foreignkey",
        )
        batch_op.drop_column("owner_id")