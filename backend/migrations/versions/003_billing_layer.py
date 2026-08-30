"""Billing foundation: accounts, plans, entitlements, payment_transactions.

Revision ID: 003
Revises: 002
"""
from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "billing_accounts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_billing_accounts_email", "billing_accounts", ["email"])

    op.create_table(
        "billing_plans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("code", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("credits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rate_limit_per_minute", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("price_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("currency", sa.String(8), nullable=False, server_default="USD"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "billing_entitlements",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("account_id", sa.String(36), sa.ForeignKey("billing_accounts.id"), nullable=False),
        sa.Column("plan_code", sa.String(64), nullable=False),
        sa.Column("credits_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("credits_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("credits_remaining", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unlimited", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("starts_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_billing_entitlements_account_id", "billing_entitlements", ["account_id"])

    op.create_table(
        "payment_transactions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("account_id", sa.String(36), sa.ForeignKey("billing_accounts.id"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False, server_default="manual"),
        sa.Column("provider_transaction_id", sa.String(128), nullable=False),
        sa.Column("amount_cents", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("currency", sa.String(8), nullable=False, server_default="USD"),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("credits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("provider", "provider_transaction_id", name="uq_provider_tx"),
    )
    op.create_index("ix_payment_transactions_account_id", "payment_transactions", ["account_id"])

    # Link existing api_keys to accounts (nullable for backward compatibility)
    op.add_column(
        "api_keys",
        sa.Column("account_id", sa.String(36), sa.ForeignKey("billing_accounts.id"), nullable=True),
    )
    op.create_index("ix_api_keys_account_id", "api_keys", ["account_id"])

    # Seed default plans
    op.execute(
        """
        INSERT INTO billing_plans (id, code, name, credits, rate_limit_per_minute, price_cents, currency, is_active)
        VALUES
          ('plan-free', 'free', 'Free', 25, 10, 0, 'USD', true),
          ('plan-starter', 'starter', 'Starter', 1000, 60, 1000, 'USD', true),
          ('plan-pro', 'pro', 'Pro', 10000, 120, 4900, 'USD', true),
          ('plan-enterprise', 'enterprise', 'Enterprise', 0, 300, 0, 'USD', true)
        """
    )


def downgrade() -> None:
    op.drop_index("ix_api_keys_account_id", table_name="api_keys")
    op.drop_column("api_keys", "account_id")
    op.drop_table("payment_transactions")
    op.drop_table("billing_entitlements")
    op.drop_table("billing_plans")
    op.drop_table("billing_accounts")
