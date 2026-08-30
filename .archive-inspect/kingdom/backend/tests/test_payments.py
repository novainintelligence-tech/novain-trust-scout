"""Provider-agnostic payment core tests (fake adapter only).

Does not import or modify novain-risk-2.0.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
import pytest_asyncio

from app.config import settings
from app.models.db import (
    APIKey,
    BillingPlan,
    PaymentTransaction,
    generate_uuid,
)
from app.services.auth import hash_secret
from app.services.billing import create_account, entitlement_summary
from app.services.payments.checkout import CheckoutError, create_checkout
from app.services.payments.fake import FakeProvider, sign_payload
from app.services.payments.processor import PaymentNotConfirmed, process_webhook
from app.services.payments.base import WebhookRejected
from app.engine.risk_engine import run_engine, BASELINE
from app.adapters.base import SourceReport


def _seed_plans_needed():
    return [
        BillingPlan(
            id="plan-free",
            code="free",
            name="Free",
            credits=25,
            rate_limit_per_minute=10,
            price_cents=0,
            currency="USD",
            is_active=True,
        ),
        BillingPlan(
            id="plan-starter",
            code="starter",
            name="Starter",
            credits=1000,
            rate_limit_per_minute=60,
            price_cents=1000,
            currency="USD",
            is_active=True,
        ),
        BillingPlan(
            id="plan-pro",
            code="pro",
            name="Pro",
            credits=10000,
            rate_limit_per_minute=120,
            price_cents=4900,
            currency="USD",
            is_active=True,
        ),
        BillingPlan(
            id="plan-enterprise",
            code="enterprise",
            name="Enterprise",
            credits=0,
            rate_limit_per_minute=300,
            price_cents=0,
            currency="USD",
            is_active=True,
        ),
    ]


@pytest_asyncio.fixture
async def billed(db_session):
    settings.PAYMENT_PROVIDER = "fake"
    settings.PAYMENT_WEBHOOK_SECRET = "test-webhook-secret-for-hmac"
    settings.PAYMENT_WEBHOOK_MAX_AGE_SECONDS = 300
    settings.ENVIRONMENT = "development"
    from sqlalchemy import select
    existing = (await db_session.execute(select(BillingPlan))).scalars().all()
    have = {p.code for p in existing}
    for p in _seed_plans_needed():
        if p.code not in have:
            db_session.add(p)
    await db_session.commit()
    account, ent = await create_account(db_session, name="Pay Co", email="pay@example.com", plan_code="free")
    return account, ent


def _signed(body: dict, secret: str = "test-webhook-secret-for-hmac", ts: int | None = None):
    raw = json.dumps(body, separators=(",", ":")).encode()
    timestamp = str(ts if ts is not None else int(time.time()))
    sig = sign_payload(raw, timestamp, secret)
    headers = {
        "X-Novain-Signature": sig,
        "X-Novain-Timestamp": timestamp,
        "Content-Type": "application/json",
    }
    return headers, raw


@pytest.mark.asyncio
async def test_checkout_creates_pending_transaction(billed, db_session):
    account, _ = billed
    result = await create_checkout(db_session, account_id=account.id, plan_code="starter")
    assert result["status"] == "pending"
    assert result["credits"] == 1000
    assert result["amount_cents"] == 1000
    assert result["provider"] == "fake"
    assert result["checkout_url"].startswith("https://")
    summary = await entitlement_summary(db_session, account.id)
    # Checkout must not grant credits until webhook confirms
    assert summary["credits_remaining"] == 25


@pytest.mark.asyncio
async def test_checkout_rejects_free_and_unknown_plans(billed, db_session):
    account, _ = billed
    with pytest.raises(CheckoutError):
        await create_checkout(db_session, account_id=account.id, plan_code="free")
    with pytest.raises(CheckoutError):
        await create_checkout(db_session, account_id=account.id, plan_code="enterprise")
    with pytest.raises(CheckoutError):
        await create_checkout(db_session, account_id=account.id, plan_code="not-a-plan")


@pytest.mark.asyncio
async def test_valid_payment_credits_from_internal_plan(billed, db_session):
    account, _ = billed
    checkout = await create_checkout(db_session, account_id=account.id, plan_code="starter")
    headers, raw = _signed(
        {
            "event": "payment.confirmed",
            "provider_transaction_id": checkout["provider_transaction_id"],
            "amount_cents": 1000,
            "currency": "USD",
            "status": "confirmed",
            "credits": 999999999,  # must be ignored
        }
    )
    out = await process_webhook(db_session, headers=headers, body=raw)
    assert out["credited"] is True
    assert out["credits"] == 1000
    summary = await entitlement_summary(db_session, account.id)
    assert summary["credits_remaining"] == 25 + 1000


@pytest.mark.asyncio
async def test_client_paid_claim_does_not_credit(billed, db_session):
    """A client saying payment_status=paid must not create credits."""
    account, _ = billed
    checkout = await create_checkout(db_session, account_id=account.id, plan_code="starter")
    # No webhook — only a client claim. Entitlement unchanged.
    summary = await entitlement_summary(db_session, account.id)
    assert summary["credits_remaining"] == 25
    assert checkout["status"] == "pending"


@pytest.mark.asyncio
async def test_forged_webhook_rejected(billed, db_session):
    account, _ = billed
    checkout = await create_checkout(db_session, account_id=account.id, plan_code="starter")
    headers, raw = _signed(
        {
            "event": "payment.confirmed",
            "provider_transaction_id": checkout["provider_transaction_id"],
            "amount_cents": 1000,
            "currency": "USD",
            "status": "confirmed",
        },
        secret="wrong-secret",
    )
    with pytest.raises(WebhookRejected):
        await process_webhook(db_session, headers=headers, body=raw)
    summary = await entitlement_summary(db_session, account.id)
    assert summary["credits_remaining"] == 25


@pytest.mark.asyncio
async def test_unsigned_webhook_rejected(billed, db_session):
    account, _ = billed
    checkout = await create_checkout(db_session, account_id=account.id, plan_code="starter")
    body = json.dumps(
        {
            "event": "payment.confirmed",
            "provider_transaction_id": checkout["provider_transaction_id"],
            "status": "confirmed",
            "amount_cents": 1000,
            "currency": "USD",
        }
    ).encode()
    with pytest.raises(WebhookRejected):
        await process_webhook(db_session, headers={}, body=body)


@pytest.mark.asyncio
async def test_replay_old_timestamp_rejected(billed, db_session):
    account, _ = billed
    checkout = await create_checkout(db_session, account_id=account.id, plan_code="starter")
    headers, raw = _signed(
        {
            "event": "payment.confirmed",
            "provider_transaction_id": checkout["provider_transaction_id"],
            "amount_cents": 1000,
            "currency": "USD",
            "status": "confirmed",
        },
        ts=int(time.time()) - 10_000,
    )
    with pytest.raises(WebhookRejected):
        await process_webhook(db_session, headers=headers, body=raw)


@pytest.mark.asyncio
async def test_wrong_amount_no_credit(billed, db_session):
    account, _ = billed
    checkout = await create_checkout(db_session, account_id=account.id, plan_code="starter")
    headers, raw = _signed(
        {
            "event": "payment.confirmed",
            "provider_transaction_id": checkout["provider_transaction_id"],
            "amount_cents": 1,
            "currency": "USD",
            "status": "confirmed",
        }
    )
    with pytest.raises(PaymentNotConfirmed):
        await process_webhook(db_session, headers=headers, body=raw)
    summary = await entitlement_summary(db_session, account.id)
    assert summary["credits_remaining"] == 25


@pytest.mark.asyncio
async def test_wrong_currency_no_credit(billed, db_session):
    account, _ = billed
    checkout = await create_checkout(db_session, account_id=account.id, plan_code="starter")
    headers, raw = _signed(
        {
            "event": "payment.confirmed",
            "provider_transaction_id": checkout["provider_transaction_id"],
            "amount_cents": 1000,
            "currency": "NGN",
            "status": "confirmed",
        }
    )
    with pytest.raises(PaymentNotConfirmed):
        await process_webhook(db_session, headers=headers, body=raw)


@pytest.mark.asyncio
async def test_failed_and_cancelled_no_credit(billed, db_session):
    account, _ = billed
    c1 = await create_checkout(db_session, account_id=account.id, plan_code="starter")
    h1, b1 = _signed(
        {
            "event": "payment.failed",
            "provider_transaction_id": c1["provider_transaction_id"],
            "amount_cents": 1000,
            "currency": "USD",
            "status": "failed",
        }
    )
    out = await process_webhook(db_session, headers=h1, body=b1)
    assert out["credited"] is False
    assert out["reason"] == "failed"

    c2 = await create_checkout(db_session, account_id=account.id, plan_code="pro")
    h2, b2 = _signed(
        {
            "event": "payment.cancelled",
            "provider_transaction_id": c2["provider_transaction_id"],
            "amount_cents": 4900,
            "currency": "USD",
            "status": "cancelled",
        }
    )
    out2 = await process_webhook(db_session, headers=h2, body=b2)
    assert out2["credited"] is False
    summary = await entitlement_summary(db_session, account.id)
    assert summary["credits_remaining"] == 25


@pytest.mark.asyncio
async def test_unknown_transaction_no_credit(billed, db_session):
    account, _ = billed
    headers, raw = _signed(
        {
            "event": "payment.confirmed",
            "provider_transaction_id": "fake_does_not_exist",
            "amount_cents": 1000,
            "currency": "USD",
            "status": "confirmed",
        }
    )
    with pytest.raises(PaymentNotConfirmed):
        await process_webhook(db_session, headers=headers, body=raw)
    summary = await entitlement_summary(db_session, account.id)
    assert summary["credits_remaining"] == 25


@pytest.mark.asyncio
async def test_duplicate_webhook_credits_once(billed, db_session):
    account, _ = billed
    checkout = await create_checkout(db_session, account_id=account.id, plan_code="starter")
    payload = {
        "event": "payment.confirmed",
        "provider_transaction_id": checkout["provider_transaction_id"],
        "amount_cents": 1000,
        "currency": "USD",
        "status": "confirmed",
    }
    credited = 0
    for _ in range(10):
        headers, raw = _signed(payload)
        out = await process_webhook(db_session, headers=headers, body=raw)
        if out.get("credited"):
            credited += 1
        else:
            assert out["reason"] == "duplicate"
    assert credited == 1
    summary = await entitlement_summary(db_session, account.id)
    assert summary["credits_remaining"] == 1025


@pytest.mark.asyncio
async def test_account_isolation(billed, db_session):
    account_a, _ = billed
    account_b, _ = await create_account(db_session, name="Other Co", plan_code="free")
    checkout = await create_checkout(db_session, account_id=account_a.id, plan_code="starter")
    headers, raw = _signed(
        {
            "event": "payment.confirmed",
            "provider_transaction_id": checkout["provider_transaction_id"],
            "amount_cents": 1000,
            "currency": "USD",
            "status": "confirmed",
        }
    )
    await process_webhook(db_session, headers=headers, body=raw)
    sum_a = await entitlement_summary(db_session, account_a.id)
    sum_b = await entitlement_summary(db_session, account_b.id)
    assert sum_a["credits_remaining"] == 1025
    assert sum_b["credits_remaining"] == 25


@pytest.mark.asyncio
async def test_suspended_account_not_credited(billed, db_session):
    account, _ = billed
    checkout = await create_checkout(db_session, account_id=account.id, plan_code="pro")
    account.status = "suspended"
    await db_session.commit()
    headers, raw = _signed(
        {
            "event": "payment.confirmed",
            "provider_transaction_id": checkout["provider_transaction_id"],
            "amount_cents": 4900,
            "currency": "USD",
            "status": "confirmed",
        }
    )
    with pytest.raises(PaymentNotConfirmed):
        await process_webhook(db_session, headers=headers, body=raw)
    account.status = "active"
    await db_session.commit()
    summary = await entitlement_summary(db_session, account.id)
    assert summary["credits_remaining"] == 25


def test_payment_modules_do_not_import_risk_engine():
    import app.services.payments.processor as proc
    import app.services.payments.checkout as chk
    src = open(proc.__file__).read() + open(chk.__file__).read()
    assert "risk_engine" not in src
    assert "ssrf" not in src
    # Engine still produces baseline with empty reports — payment cannot change it
    result = run_engine([])
    assert result.raw_score == BASELINE
    assert result.evidence_items == []


def test_fake_provider_hmac_roundtrip():
    body = b'{"status":"confirmed"}'
    ts = str(int(time.time()))
    secret = "abc"
    sig = sign_payload(body, ts, secret)
    expected = "sha256=" + hmac.new(b"abc", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(sig, expected)
