"""Server-side checkout. Client cannot declare 'I paid'."""
from __future__ import annotations

from typing import Any, Dict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db import BillingAccount, BillingPlan, PaymentTransaction, generate_uuid, utcnow
from app.services.payments.base import PaymentProviderError
from app.services.payments.registry import get_payment_provider
import structlog

logger = structlog.get_logger()

# Prepaid packages that can be purchased via checkout. Free/enterprise are not self-serve.
CHECKOUT_PLANS = frozenset({"starter", "pro"})


class CheckoutError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


async def create_checkout(
    db: AsyncSession,
    *,
    account_id: str,
    plan_code: str,
) -> Dict[str, Any]:
    plan_code = (plan_code or "").strip().lower()
    if plan_code not in CHECKOUT_PLANS:
        raise CheckoutError("plan_code must be one of: starter, pro")

    ar = await db.execute(select(BillingAccount).where(BillingAccount.id == account_id))
    account = ar.scalar_one_or_none()
    if not account:
        raise CheckoutError("Billing account not found.")
    if account.status != "active":
        raise CheckoutError("Account is not active.")

    pr = await db.execute(
        select(BillingPlan).where(BillingPlan.code == plan_code, BillingPlan.is_active == True)
    )
    plan = pr.scalar_one_or_none()
    if not plan:
        raise CheckoutError("Plan is not available.")
    if plan.price_cents <= 0 or plan.credits <= 0:
        raise CheckoutError("Plan is not available for self-serve checkout.")

    internal_id = generate_uuid()
    provider = get_payment_provider()
    try:
        result = await provider.create_checkout(
            account_id=account_id,
            plan_code=plan_code,
            amount_cents=plan.price_cents,
            currency=plan.currency or "USD",
            internal_transaction_id=internal_id,
        )
    except PaymentProviderError as e:
        raise CheckoutError(str(e)) from e

    tx = PaymentTransaction(
        id=internal_id,
        account_id=account_id,
        provider=result.provider,
        provider_transaction_id=result.provider_transaction_id,
        amount_cents=plan.price_cents,
        currency=(plan.currency or "USD").upper(),
        status="pending",
        credits=plan.credits,  # expected credits from internal plan, not client
        plan_code=plan_code,
        expected_amount_cents=plan.price_cents,
        expected_currency=(plan.currency or "USD").upper(),
        checkout_session_id=result.checkout_session_id,
        credited=False,
        meta={"checkout": True},
        created_at=utcnow(),
    )
    db.add(tx)
    await db.commit()
    await db.refresh(tx)

    logger.info(
        "checkout_created",
        account_id=account_id,
        plan_code=plan_code,
        provider=result.provider,
        transaction_id=tx.id,
        provider_transaction_id=result.provider_transaction_id,
        amount_cents=plan.price_cents,
    )
    return {
        "transaction_id": tx.id,
        "provider": result.provider,
        "provider_transaction_id": result.provider_transaction_id,
        "plan_code": plan_code,
        "amount_cents": plan.price_cents,
        "currency": (plan.currency or "USD").upper(),
        "credits": plan.credits,
        "status": "pending",
        "checkout_url": result.checkout_url,
    }
