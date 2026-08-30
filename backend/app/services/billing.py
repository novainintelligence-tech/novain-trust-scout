"""
NOVAIN TRUST monetization layer.

PAYMENT / ENTITLEMENT → API ACCESS → VERIFICATION

Never modifies risk engine, evidence, scores, or SSRF.
Credit consumption is atomic (row lock) to prevent concurrent overspend.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Tuple
from sqlalchemy import select, update, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db import (
    APIKey,
    BillingAccount,
    BillingEntitlement,
    BillingPlan,
    PaymentTransaction,
    generate_uuid,
    utcnow,
)
from app.config import settings
import structlog

logger = structlog.get_logger()


class InsufficientCreditsError(Exception):
    def __init__(self, message: str = "Insufficient verification credits."):
        self.message = message
        super().__init__(message)


class AccountSuspendedError(Exception):
    def __init__(self, message: str = "Account is suspended."):
        self.message = message
        super().__init__(message)


class EntitlementInactiveError(Exception):
    def __init__(self, message: str = "No active entitlement."):
        self.message = message
        super().__init__(message)


async def create_account(
    db: AsyncSession,
    name: str,
    email: Optional[str] = None,
    plan_code: str = "free",
) -> Tuple[BillingAccount, BillingEntitlement]:
    account = BillingAccount(
        id=generate_uuid(),
        name=name,
        email=email,
        status="active",
    )
    db.add(account)
    await db.flush()

    plan = await _get_plan(db, plan_code)
    if not plan:
        plan_code = "free"
        plan = await _get_plan(db, "free")

    unlimited = plan_code == "enterprise" or (plan and plan.credits == 0 and plan_code == "enterprise")
    credits = 0 if unlimited else (plan.credits if plan else 25)

    ent = BillingEntitlement(
        id=generate_uuid(),
        account_id=account.id,
        plan_code=plan_code,
        credits_total=credits,
        credits_used=0,
        credits_remaining=credits if not unlimited else 0,
        unlimited=bool(unlimited),
        status="active",
        starts_at=utcnow(),
    )
    db.add(ent)
    await db.commit()
    await db.refresh(account)
    await db.refresh(ent)
    logger.info("billing_account_created", account_id=account.id, plan=plan_code)
    return account, ent


async def _get_plan(db: AsyncSession, code: str) -> Optional[BillingPlan]:
    r = await db.execute(select(BillingPlan).where(BillingPlan.code == code, BillingPlan.is_active == True))
    return r.scalar_one_or_none()


async def attach_key_to_account(db: AsyncSession, api_key: APIKey, account_id: str) -> None:
    api_key.account_id = account_id
    await db.commit()


async def get_active_entitlement(db: AsyncSession, account_id: str) -> Optional[BillingEntitlement]:
    r = await db.execute(
        select(BillingEntitlement)
        .where(
            BillingEntitlement.account_id == account_id,
            BillingEntitlement.status == "active",
        )
        .order_by(BillingEntitlement.created_at.desc())
    )
    ents = r.scalars().all()
    now = utcnow()
    for e in ents:
        if e.expires_at is not None:
            exp = e.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < now:
                e.status = "expired"
                continue
        return e
    await db.commit()
    return None


async def consume_credit(db: AsyncSession, api_key: APIKey) -> Optional[str]:
    """
    Atomic credit consumption for one billable verification.
    Returns entitlement_id if consumed (or unlimited).
    Raises InsufficientCreditsError / AccountSuspendedError / EntitlementInactiveError.

    If BILLING_ENFORCE is false, no-op (development).
    If key has no account_id, skip enforcement (legacy keys) unless BILLING_REQUIRE_ACCOUNT.
    """
    if not getattr(settings, "BILLING_ENFORCE", False):
        return None

    if not api_key.account_id:
        if getattr(settings, "BILLING_REQUIRE_ACCOUNT", False):
            raise EntitlementInactiveError("API key is not linked to a billing account.")
        return None

    # Account status
    ar = await db.execute(select(BillingAccount).where(BillingAccount.id == api_key.account_id))
    account = ar.scalar_one_or_none()
    if not account or account.status != "active":
        raise AccountSuspendedError()

    # Prefer PostgreSQL atomic UPDATE ... WHERE remaining > 0 RETURNING
    dialect = db.bind.dialect.name if db.bind else ""
    if dialect == "postgresql":
        # 1) Try unlimited entitlement (usage counter only)
        result = await db.execute(
            text(
                """
                UPDATE billing_entitlements
                SET credits_used = credits_used + 1,
                    updated_at = NOW()
                WHERE id = (
                    SELECT id FROM billing_entitlements
                    WHERE account_id = :account_id
                      AND status = 'active'
                      AND unlimited = true
                      AND (expires_at IS NULL OR expires_at > NOW())
                    ORDER BY created_at DESC
                    LIMIT 1
                    FOR UPDATE
                )
                RETURNING id
                """
            ),
            {"account_id": api_key.account_id},
        )
        row = result.fetchone()
        if row:
            await db.commit()
            return row[0]

        # 2) Finite credits: atomic decrement
        result = await db.execute(
            text(
                """
                UPDATE billing_entitlements
                SET credits_used = credits_used + 1,
                    credits_remaining = credits_remaining - 1,
                    updated_at = NOW(),
                    status = CASE
                        WHEN credits_remaining - 1 <= 0 THEN 'exhausted'
                        ELSE status
                    END
                WHERE id = (
                    SELECT id FROM billing_entitlements
                    WHERE account_id = :account_id
                      AND status = 'active'
                      AND unlimited = false
                      AND credits_remaining > 0
                      AND (expires_at IS NULL OR expires_at > NOW())
                    ORDER BY created_at DESC
                    LIMIT 1
                    FOR UPDATE
                )
                AND credits_remaining > 0
                RETURNING id
                """
            ),
            {"account_id": api_key.account_id},
        )
        row = result.fetchone()
        await db.commit()
        if not row:
            raise InsufficientCreditsError()
        return row[0]

    # SQLite / fallback: select + update with check
    ent = await get_active_entitlement(db, api_key.account_id)
    if not ent:
        raise EntitlementInactiveError()
    if ent.unlimited:
        ent.credits_used = (ent.credits_used or 0) + 1
        await db.commit()
        return ent.id
    if (ent.credits_remaining or 0) <= 0:
        ent.status = "exhausted"
        await db.commit()
        raise InsufficientCreditsError()
    ent.credits_used = (ent.credits_used or 0) + 1
    ent.credits_remaining = ent.credits_remaining - 1
    if ent.credits_remaining <= 0:
        ent.status = "exhausted"
    await db.commit()
    return ent.id


async def apply_plan_credits(
    db: AsyncSession,
    *,
    account_id: str,
    plan_code: str,
    credits: int,
) -> BillingEntitlement:
    """
    Grant credits from an internal plan. Caller must already have validated the payment.
    Does not create a payment_transactions row (processor owns that).
    """
    if credits <= 0:
        raise ValueError("credits must be positive")
    ent = await get_active_entitlement(db, account_id)
    if ent and ent.status in ("active", "exhausted") and not ent.unlimited:
        ent.credits_total = (ent.credits_total or 0) + credits
        ent.credits_remaining = (ent.credits_remaining or 0) + credits
        ent.status = "active"
        ent.plan_code = plan_code or ent.plan_code
        return ent
    ent = BillingEntitlement(
        id=generate_uuid(),
        account_id=account_id,
        plan_code=plan_code,
        credits_total=credits,
        credits_used=0,
        credits_remaining=credits,
        unlimited=False,
        status="active",
        starts_at=utcnow(),
    )
    db.add(ent)
    return ent


async def credit_account_manual(
    db: AsyncSession,
    account_id: str,
    credits: int,
    plan_code: str = "starter",
    provider_transaction_id: Optional[str] = None,
    amount_cents: int = 0,
    note: str = "manual_credit",
) -> PaymentTransaction:
    """
    Phase 1: admin/manual credit. Idempotent on (provider, provider_transaction_id).
    Does not call payment providers.
    """
    provider = "manual"
    tx_id = provider_transaction_id or f"manual-{generate_uuid()}"

    existing = await db.execute(
        select(PaymentTransaction).where(
            PaymentTransaction.provider == provider,
            PaymentTransaction.provider_transaction_id == tx_id,
        )
    )
    if existing.scalar_one_or_none():
        raise ValueError("Duplicate provider_transaction_id")

    tx = PaymentTransaction(
        id=generate_uuid(),
        account_id=account_id,
        provider=provider,
        provider_transaction_id=tx_id,
        amount_cents=amount_cents,
        currency="USD",
        status="confirmed",
        credits=credits,
        plan_code=plan_code,
        expected_amount_cents=amount_cents,
        expected_currency="USD",
        credited=True,
        meta={"note": note},
        confirmed_at=utcnow(),
    )
    db.add(tx)
    await apply_plan_credits(db, account_id=account_id, plan_code=plan_code, credits=credits)
    await db.commit()
    await db.refresh(tx)
    logger.info("manual_credit", account_id=account_id, credits=credits, tx=tx_id)
    return tx


async def entitlement_summary(db: AsyncSession, account_id: str) -> dict:
    ent = await get_active_entitlement(db, account_id)
    if not ent:
        return {"status": "none", "credits_remaining": 0}
    return {
        "entitlement_id": ent.id,
        "plan_code": ent.plan_code,
        "credits_total": ent.credits_total,
        "credits_used": ent.credits_used,
        "credits_remaining": ent.credits_remaining if not ent.unlimited else None,
        "unlimited": ent.unlimited,
        "status": ent.status,
        "expires_at": ent.expires_at.isoformat() if ent.expires_at else None,
    }
