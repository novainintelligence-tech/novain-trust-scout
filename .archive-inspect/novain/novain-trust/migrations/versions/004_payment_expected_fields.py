"""Payment checkout expected fields for provider-agnostic billing.

Revision ID: 004
Revises: 003
"""
from alembic import op
import sqlalchemy as sa

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("payment_transactions", sa.Column("plan_code", sa.String(64), nullable=True))
    op.add_column("payment_transactions", sa.Column("expected_amount_cents", sa.Integer(), nullable=True))
    op.add_column("payment_transactions", sa.Column("expected_currency", sa.String(8), nullable=True))
    op.add_column("payment_transactions", sa.Column("checkout_session_id", sa.String(128), nullable=True))
    op.add_column(
        "payment_transactions",
        sa.Column("credited", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index(
        "ix_payment_transactions_checkout_session_id",
        "payment_transactions",
        ["checkout_session_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_payment_transactions_checkout_session_id", table_name="payment_transactions")
    op.drop_column("payment_transactions", "credited")
    op.drop_column("payment_transactions", "checkout_session_id")
    op.drop_column("payment_transactions", "expected_currency")
    op.drop_column("payment_transactions", "expected_amount_cents")
    op.drop_column("payment_transactions", "plan_code")
