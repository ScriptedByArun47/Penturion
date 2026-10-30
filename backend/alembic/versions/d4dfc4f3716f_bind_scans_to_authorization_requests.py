"""Bind scans to authorization requests."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# Revision identifiers.
revision: str = "d4dfc4f3716f"
down_revision: Union[str, Sequence[str], None] = "33a5d24af8e4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        batch_op.add_column(
            sa.Column(
                "authorization_request_id",
                sa.String(length=36),
                nullable=True,
            )
        )

        batch_op.create_foreign_key(
            "fk_scans_authorization_request_id",
            "authorization_requests",
            ["authorization_request_id"],
            ["id"],
            ondelete="RESTRICT",
        )

        batch_op.create_index(
            "ix_scans_authorization_request_id",
            ["authorization_request_id"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_index("ix_scans_authorization_request_id")

        batch_op.drop_constraint(
            "fk_scans_authorization_request_id",
            type_="foreignkey",
        )

        batch_op.drop_column("authorization_request_id")