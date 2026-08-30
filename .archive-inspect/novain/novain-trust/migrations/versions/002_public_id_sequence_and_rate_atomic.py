"""PostgreSQL sequence for public IDs + atomic rate limit support

Revision ID: 002
Revises: 001
"""
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.execute("CREATE SEQUENCE IF NOT EXISTS novain_public_id_seq START WITH 1 INCREMENT BY 1")
        # Align sequence with existing next_value if any
        op.execute("""
        SELECT setval(
            'novain_public_id_seq',
            GREATEST(
                (SELECT COALESCE(MAX(next_value), 1) FROM verification_public_id_sequence),
                1
            )
        )
        """)
    # Ensure unique constraint exists on public_id (already in 001)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("DROP SEQUENCE IF EXISTS novain_public_id_seq")
