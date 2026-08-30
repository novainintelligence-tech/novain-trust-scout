"""
NOVAIN TRUST persistence models.
Evidence is the source of truth. Score contributions are always traceable.
"""

from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Boolean, Text, ForeignKey,
    JSON, Index, UniqueConstraint, BigInteger
)
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime, timezone
import uuid

Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    return str(uuid.uuid4())


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(String(36), primary_key=True, default=generate_uuid)  # key_id
    key_prefix = Column(String(16), nullable=False)  # nv_live_ or nv_test_
    environment = Column(String(16), nullable=False, default="live")  # live | test
    secret_hash = Column(String(128), nullable=False)
    name = Column(String(200), nullable=False)
    owner_email = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    rate_limit_per_minute = Column(Integer, default=30, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    request_count = Column(Integer, default=0)
    account_id = Column(String(36), ForeignKey("billing_accounts.id"), nullable=True, index=True)

    account = relationship("BillingAccount", back_populates="api_keys")
    usages = relationship("APIUsage", back_populates="api_key")
    rate_windows = relationship("APIKeyRateWindow", back_populates="api_key")


class APIKeyRateWindow(Base):
    """
    Atomic per-key per-minute rate limit counters.
    window_start is floor of UTC minute (seconds = 0).
    """
    __tablename__ = "api_key_rate_windows"
    __table_args__ = (
        UniqueConstraint("api_key_id", "window_start", name="uq_rate_window_key_minute"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    api_key_id = Column(String(36), ForeignKey("api_keys.id"), nullable=False, index=True)
    window_start = Column(DateTime(timezone=True), nullable=False, index=True)
    count = Column(Integer, nullable=False, default=0)

    api_key = relationship("APIKey", back_populates="rate_windows")


class APIUsage(Base):
    __tablename__ = "api_usage"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    request_id = Column(String(36), nullable=False, index=True)
    api_key_id = Column(String(36), ForeignKey("api_keys.id"), nullable=False, index=True)
    endpoint = Column(String(128), nullable=False)
    verification_id = Column(String(36), nullable=True, index=True)
    status_code = Column(Integer, nullable=False)
    latency_ms = Column(Float, nullable=True)
    units = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    api_key = relationship("APIKey", back_populates="usages")


class VerificationSource(Base):
    __tablename__ = "verification_sources"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(64), unique=True, nullable=False)
    status = Column(String(20), default="ACTIVE", nullable=False)
    description = Column(String(255), nullable=True)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    meta = Column(JSON, nullable=True)


class VerificationPublicIdSequence(Base):
    """
    Single-row table for atomic public verification ID allocation.
    next_value is the next integer to assign (starts at 1).
    """
    __tablename__ = "verification_public_id_sequence"

    id = Column(Integer, primary_key=True)  # always 1
    next_value = Column(BigInteger, nullable=False, default=1)


class Verification(Base):
    __tablename__ = "verifications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    public_id = Column(String(32), unique=True, nullable=False, index=True)
    target = Column(Text, nullable=False)
    target_type = Column(String(32), default="website", nullable=False)
    normalized_domain = Column(String(255), nullable=True, index=True)

    score = Column(Integer, nullable=False)
    raw_score = Column(Integer, nullable=False)
    risk_level = Column(String(20), nullable=False)
    confidence = Column(Float, nullable=False)
    coverage = Column(Float, nullable=False)
    status = Column(String(20), nullable=False)
    capped = Column(Boolean, default=False, nullable=False)
    recommendation = Column(String(64), nullable=False)

    engine = Column(String(64), default="novain-risk-2.0", nullable=False)
    request_id = Column(String(36), nullable=True, index=True)
    api_key_id = Column(String(36), ForeignKey("api_keys.id"), nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow)

    evidence = relationship("VerificationEvidence", back_populates="verification")
    contributions = relationship("ScoreContribution", back_populates="verification")
    risk_gates = relationship("VerificationRiskGate", back_populates="verification")
    checks = relationship("VerificationCheck", back_populates="verification")


class VerificationCheck(Base):
    __tablename__ = "verification_checks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    verification_id = Column(String(36), ForeignKey("verifications.id"), nullable=False, index=True)
    check_id = Column(String(64), nullable=False)
    source = Column(String(32), nullable=False)
    status = Column(String(20), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    verification = relationship("Verification", back_populates="checks")


class VerificationEvidence(Base):
    __tablename__ = "verification_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    evidence_id = Column(String(32), unique=True, nullable=False, index=True)
    verification_id = Column(String(36), ForeignKey("verifications.id"), nullable=False, index=True)
    check_id = Column(String(64), nullable=True)
    source_id = Column(String(32), nullable=False)
    signal = Column(String(64), nullable=False)
    observation = Column(JSON, nullable=True)
    result = Column(String(20), nullable=False)
    severity = Column(String(20), nullable=True)
    confidence = Column(Float, default=0.0)
    weight = Column(Integer, default=0)
    observed_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    raw_reference = Column(Text, nullable=True)

    verification = relationship("Verification", back_populates="evidence")
    contributions = relationship("ScoreContribution", back_populates="evidence")


class ScoreContribution(Base):
    __tablename__ = "verification_score_contributions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    verification_id = Column(String(36), ForeignKey("verifications.id"), nullable=False, index=True)
    evidence_id = Column(String(36), ForeignKey("verification_evidence.id"), nullable=False, index=True)
    check_id = Column(String(64), nullable=True)
    rule_id = Column(String(64), nullable=True)
    contribution = Column(Integer, nullable=False)
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    verification = relationship("Verification", back_populates="contributions")
    evidence = relationship("VerificationEvidence", back_populates="contributions")


class VerificationRiskGate(Base):
    __tablename__ = "verification_risk_gates"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    verification_id = Column(String(36), ForeignKey("verifications.id"), nullable=False, index=True)
    gate = Column(String(64), nullable=False)
    cap = Column(Integer, nullable=True)
    reason = Column(Text, nullable=False)
    triggered = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    verification = relationship("Verification", back_populates="risk_gates")


class RiskRule(Base):
    __tablename__ = "risk_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    rule_id = Column(String(64), unique=True, nullable=False)
    signal = Column(String(64), nullable=False)
    description = Column(Text, nullable=True)
    pass_contribution = Column(Integer, default=0)
    fail_contribution = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)



# =============================================================================
# Monetization layer (access only — never touches risk engine / evidence)
# =============================================================================

class BillingAccount(Base):
    """Customer/account that owns API keys and entitlements."""
    __tablename__ = "billing_accounts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(200), nullable=False)
    email = Column(String(255), nullable=True, index=True)
    status = Column(String(32), nullable=False, default="active")  # active | suspended | closed
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    api_keys = relationship("APIKey", back_populates="account")
    entitlements = relationship("BillingEntitlement", back_populates="account")
    transactions = relationship("PaymentTransaction", back_populates="account")


class BillingPlan(Base):
    """Catalog of plans (credits + default rate limit)."""
    __tablename__ = "billing_plans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    code = Column(String(64), unique=True, nullable=False)  # free | starter | pro | enterprise
    name = Column(String(120), nullable=False)
    credits = Column(Integer, nullable=False, default=0)  # 0 = unlimited (enterprise)
    rate_limit_per_minute = Column(Integer, nullable=False, default=30)
    price_cents = Column(Integer, nullable=False, default=0)
    currency = Column(String(8), nullable=False, default="USD")
    is_active = Column(Boolean, default=True, nullable=False)
    meta = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class BillingEntitlement(Base):
    """
    Active credit balance for an account.
    Atomic consume decrements credits_remaining under row lock.
    """
    __tablename__ = "billing_entitlements"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    account_id = Column(String(36), ForeignKey("billing_accounts.id"), nullable=False, index=True)
    plan_code = Column(String(64), nullable=False)
    credits_total = Column(Integer, nullable=False, default=0)
    credits_used = Column(Integer, nullable=False, default=0)
    credits_remaining = Column(Integer, nullable=False, default=0)
    unlimited = Column(Boolean, default=False, nullable=False)
    status = Column(String(32), nullable=False, default="active")  # active | exhausted | expired | suspended
    starts_at = Column(DateTime(timezone=True), default=utcnow)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    account = relationship("BillingAccount", back_populates="entitlements")


class PaymentTransaction(Base):
    """
    Provider-neutral payment record.

    Credits are always derived from the internal plan_code, never from
    untrusted webhook/client fields.
    """
    __tablename__ = "payment_transactions"
    __table_args__ = (
        UniqueConstraint("provider", "provider_transaction_id", name="uq_provider_tx"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    account_id = Column(String(36), ForeignKey("billing_accounts.id"), nullable=False, index=True)
    provider = Column(String(32), nullable=False, default="manual")  # fake | manual | paystack | moonpay | stripe
    provider_transaction_id = Column(String(128), nullable=False)
    amount_cents = Column(Integer, nullable=False, default=0)
    currency = Column(String(8), nullable=False, default="USD")
    status = Column(String(32), nullable=False, default="pending")  # pending | confirmed | failed | cancelled | refunded
    credits = Column(Integer, nullable=False, default=0)
    plan_code = Column(String(64), nullable=True)
    expected_amount_cents = Column(Integer, nullable=True)
    expected_currency = Column(String(8), nullable=True)
    checkout_session_id = Column(String(128), nullable=True)
    credited = Column(Boolean, default=False, nullable=False)
    meta = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    confirmed_at = Column(DateTime(timezone=True), nullable=True)

    account = relationship("BillingAccount", back_populates="transactions")
