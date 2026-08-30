"""
Confirm payments from verified provider events.

Fail closed. Credits come from the internal plan, never from webhook fields.
Idempotent on (provider, provider_transaction_id) + credited flag.
"""
from __future__ import annotations

from typing import Any, Dict, Mapping

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db import BillingAccount, BillingPlan, PaymentTransaction, utcnow
from app.services.billing import apply_plan_credits
from app.services.payments.base import WebhookRejected
from app.services.payments.registry import get_payment_provider
import structlog

logger = structlog.get_logger()


class PaymentNotConfirmed(Exception):
    def __init__(self, message: str = "Payment is not confirmed."):
        self.message = message
        super().__init__(message)


async def process_webhook(
    db: AsyncSession,
    *,
    headers: Mapping[str, str],
    body: bytes,
    provider_name: str | None = None,
) -> Dict[str, Any]:
    provider = get_payment_provider(provider_name)
    event = provider.verify_webhook(headers, body)

    logger.info(
        "webhook_verified",
        provider=event.provider,
        provider_transaction_id=event.provider_transaction_id,
        status=event.status,
        event_type=event.event_type,
    )

    result = await db.execute(
        select(PaymentTransaction).where(
            PaymentTransaction.provider == event.provider,
            PaymentTransaction.provider_transaction_id == event.provider_transaction_id,
        )
    )
    tx = result.scalar_one_or_none()
    if not tx:
        # Unknown transaction — never credit from a webhook that has no checkout record.
        logger.info(
            "webhook_unknown_transaction",
            provider=event.provider,
            provider_transaction_id=event.provider_transaction_id,
        )
        raise PaymentNotConfirmed("Unknown payment transaction.")

    if event.status in ("failed", "cancelled"):
        if tx.status == "pending":
            tx.status = event.status
            await db.commit()
        return {
            "accepted": True,
            "credited": False,
            "reason": event.status,
            "transaction_id": tx.id,
        }

    if event.status != "confirmed":
        return {
            "accepted": True,
            "credited": False,
            "reason": "not_confirmed",
            "transaction_id": tx.id,
        }

    # Amount / currency must match the server-side expected plan.
    expected_amount = tx.expected_amount_cents if tx.expected_amount_cents is not None else tx.amount_cents
    expected_currency = (tx.expected_currency or tx.currency or "USD").upper()
    if event.amount_cents is not None and int(event.amount_cents) != int(expected_amount):
        logger.info(
            "webhook_amount_mismatch",
            transaction_id=tx.id,
            expected=expected_amount,
            observed=event.amount_cents,
        )
        raise PaymentNotConfirmed("Payment amount does not match expected plan price.")
    if event.currency is not None and event.currency.upper() != expected_currency:
        logger.info(
            "webhook_currency_mismatch",
            transaction_id=tx.id,
            expected=expected_currency,
            observed=event.currency,
        )
        raise PaymentNotConfirmed("Payment currency does not match expected plan currency.")

    # Account isolation: credit only tx.account_id from the checkout record.
    ar = await db.execute(select(BillingAccount).where(BillingAccount.id == tx.account_id))
    account = ar.scalar_one_or_none()
    if not account or account.status != "active":
        raise PaymentNotConfirmed("Account is not eligible for credits.")

    if tx.credited or tx.status == "confirmed":
        return {
            "accepted": True,
            "credited": False,
            "reason": "duplicate",
            "transaction_id": tx.id,
        }

    plan_code = tx.plan_code
    if not plan_code:
        raise PaymentNotConfirmed("Payment has no internal plan_code.")

    pr = await db.execute(select(BillingPlan).where(BillingPlan.code == plan_code, BillingPlan.is_active == True))
    plan = pr.scalar_one_or_none()
    if not plan:
        raise PaymentNotConfirmed("Internal plan is not available.")

    # Credits from plan catalog — ignore any credit count in the webhook.
    credits = int(plan.credits or 0)
    if credits <= 0:
        raise PaymentNotConfirmed("Plan does not grant prepaid credits.")

    await apply_plan_credits(db, account_id=tx.account_id, plan_code=plan_code, credits=credits)
    tx.status = "confirmed"
    tx.credited = True
    tx.credits = credits
    tx.confirmed_at = utcnow()
    await db.commit()

    logger.info(
        "payment_credited",
        account_id=tx.account_id,
        transaction_id=tx.id,
        plan_code=plan_code,
        credits=credits,
        provider=tx.provider,
        provider_transaction_id=tx.provider_transaction_id,
    )
    return {
        "accepted": True,
        "credited": True,
        "reason": "confirmed",
        "transaction_id": tx.id,
        "credits": credits,
        "plan_code": plan_code,
    }
