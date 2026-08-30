"""Initial NOVAIN TRUST schema

Revision ID: 001
Revises:
Create Date: 2026-08-29
"""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("key_prefix", sa.String(16), nullable=False),
        sa.Column("environment", sa.String(16), nullable=False, server_default="live"),
        sa.Column("secret_hash", sa.String(128), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("owner_email", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rate_limit_per_minute", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("request_count", sa.Integer(), server_default="0"),
    )

    op.create_table(
        "api_key_rate_windows",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("api_key_id", sa.String(36), sa.ForeignKey("api_keys.id"), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("api_key_id", "window_start", name="uq_rate_window_key_minute"),
    )
    op.create_index("ix_api_key_rate_windows_api_key_id", "api_key_rate_windows", ["api_key_id"])
    op.create_index("ix_api_key_rate_windows_window_start", "api_key_rate_windows", ["window_start"])

    op.create_table(
        "api_usage",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("api_key_id", sa.String(36), sa.ForeignKey("api_keys.id"), nullable=False),
        sa.Column("endpoint", sa.String(128), nullable=False),
        sa.Column("verification_id", sa.String(36), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("units", sa.Integer(), server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_usage_request_id", "api_usage", ["request_id"])
    op.create_index("ix_api_usage_api_key_id", "api_usage", ["api_key_id"])
    op.create_index("ix_api_usage_verification_id", "api_usage", ["verification_id"])

    op.create_table(
        "verification_sources",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(64), unique=True, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="ACTIVE"),
        sa.Column("description", sa.String(255), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=True),
    )

    op.create_table(
        "verification_public_id_sequence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("next_value", sa.BigInteger(), nullable=False, server_default="1"),
    )

    op.create_table(
        "verifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("public_id", sa.String(32), unique=True, nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False, server_default="website"),
        sa.Column("normalized_domain", sa.String(255), nullable=True),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("raw_score", sa.Integer(), nullable=False),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("coverage", sa.Float(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("capped", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("recommendation", sa.String(64), nullable=False),
        sa.Column("engine", sa.String(64), nullable=False, server_default="novain-risk-2.0"),
        sa.Column("request_id", sa.String(36), nullable=True),
        sa.Column("api_key_id", sa.String(36), sa.ForeignKey("api_keys.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_verifications_public_id", "verifications", ["public_id"])
    op.create_index("ix_verifications_normalized_domain", "verifications", ["normalized_domain"])
    op.create_index("ix_verifications_request_id", "verifications", ["request_id"])

    op.create_table(
        "verification_checks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("verification_id", sa.String(36), sa.ForeignKey("verifications.id"), nullable=False),
        sa.Column("check_id", sa.String(64), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_verification_checks_verification_id", "verification_checks", ["verification_id"])

    op.create_table(
        "verification_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("evidence_id", sa.String(32), unique=True, nullable=False),
        sa.Column("verification_id", sa.String(36), sa.ForeignKey("verifications.id"), nullable=False),
        sa.Column("check_id", sa.String(64), nullable=True),
        sa.Column("source_id", sa.String(32), nullable=False),
        sa.Column("signal", sa.String(64), nullable=False),
        sa.Column("observation", sa.JSON(), nullable=True),
        sa.Column("result", sa.String(20), nullable=False),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("confidence", sa.Float(), server_default="0"),
        sa.Column("weight", sa.Integer(), server_default="0"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw_reference", sa.Text(), nullable=True),
    )
    op.create_index("ix_verification_evidence_evidence_id", "verification_evidence", ["evidence_id"])
    op.create_index("ix_verification_evidence_verification_id", "verification_evidence", ["verification_id"])

    op.create_table(
        "verification_score_contributions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("verification_id", sa.String(36), sa.ForeignKey("verifications.id"), nullable=False),
        sa.Column("evidence_id", sa.String(36), sa.ForeignKey("verification_evidence.id"), nullable=False),
        sa.Column("check_id", sa.String(64), nullable=True),
        sa.Column("rule_id", sa.String(64), nullable=True),
        sa.Column("contribution", sa.Integer(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_score_contrib_verification_id", "verification_score_contributions", ["verification_id"])
    op.create_index("ix_score_contrib_evidence_id", "verification_score_contributions", ["evidence_id"])

    op.create_table(
        "verification_risk_gates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("verification_id", sa.String(36), sa.ForeignKey("verifications.id"), nullable=False),
        sa.Column("gate", sa.String(64), nullable=False),
        sa.Column("cap", sa.Integer(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("triggered", sa.Boolean(), server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_risk_gates_verification_id", "verification_risk_gates", ["verification_id"])

    op.create_table(
        "risk_rules",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("rule_id", sa.String(64), unique=True, nullable=False),
        sa.Column("signal", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("pass_contribution", sa.Integer(), server_default="0"),
        sa.Column("fail_contribution", sa.Integer(), server_default="0"),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true")),
    )

    # Seed sequence
    op.execute("INSERT INTO verification_public_id_sequence (id, next_value) VALUES (1, 1)")


def downgrade() -> None:
    op.drop_table("risk_rules")
    op.drop_table("verification_risk_gates")
    op.drop_table("verification_score_contributions")
    op.drop_table("verification_evidence")
    op.drop_table("verification_checks")
    op.drop_table("verifications")
    op.drop_table("verification_public_id_sequence")
    op.drop_table("verification_sources")
    op.drop_table("api_usage")
    op.drop_table("api_key_rate_windows")
    op.drop_table("api_keys")
