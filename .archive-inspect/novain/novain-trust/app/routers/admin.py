"""
Protected administrative operations for API key lifecycle and ops metrics.
Requires X-Admin-Token matching settings.ADMIN_TOKEN (constant-time compare).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import ORJSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.errors import error_response
from app.middleware.auth import get_or_create_request_id
from app.models.db import APIKey
from app.models.schemas import CreateKeyRequest, CreateKeyResponse, KeyListItem
from app.services.auth import constant_time_compare, create_api_key, revoke_key
from app.services import metrics as metrics_svc
from app.services.circuit_breaker import provider_breakers
from app.services import verify_cache

router = APIRouter(prefix="/api/admin/v1", tags=["Admin"], include_in_schema=False)


def _admin_ok(token: Optional[str]) -> bool:
    return bool(token) and constant_time_compare(token, settings.ADMIN_TOKEN)


@router.post("/keys", response_model=CreateKeyResponse)
async def admin_create_key(
    body: CreateKeyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    rid = get_or_create_request_id(request)
    if not _admin_ok(x_admin_token):
        return error_response("UNAUTHORIZED", "Admin token required.", 401, rid)
    if settings.is_production and body.environment == "test":
        return error_response(
            "INVALID_REQUEST",
            "Test keys cannot be created when ENVIRONMENT=production.",
            400,
            rid,
        )
    env = "live" if body.environment == "live" else "test"
    record, full_key = await create_api_key(
        db,
        name=body.name,
        owner_email=body.owner_email,
        environment=env,
        rate_limit_per_minute=body.rate_limit_per_minute,
        expires_days=body.expires_days,
    )
    return CreateKeyResponse(
        key_id=record.id,
        api_key=full_key,
        name=record.name,
        environment=env,
        rate_limit_per_minute=record.rate_limit_per_minute,
        created_at=record.created_at or datetime.now(timezone.utc),
    )


@router.get("/keys", response_model=List[KeyListItem])
async def admin_list_keys(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    rid = get_or_create_request_id(request)
    if not _admin_ok(x_admin_token):
        return error_response("UNAUTHORIZED", "Admin token required.", 401, rid)
    result = await db.execute(select(APIKey).order_by(APIKey.created_at.desc()))
    keys = result.scalars().all()
    return [
        KeyListItem(
            key_id=k.id,
            name=k.name,
            prefix=k.key_prefix,
            is_active=k.is_active,
            is_revoked=k.is_revoked,
            rate_limit_per_minute=k.rate_limit_per_minute,
            created_at=k.created_at,
            last_used_at=k.last_used_at,
            request_count=k.request_count or 0,
        )
        for k in keys
    ]


@router.post("/keys/{key_id}/revoke")
async def admin_revoke_key(
    key_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    rid = get_or_create_request_id(request)
    if not _admin_ok(x_admin_token):
        return error_response("UNAUTHORIZED", "Admin token required.", 401, rid)
    ok = await revoke_key(db, key_id)
    if not ok:
        return error_response("NOT_FOUND", "Key not found.", 404, rid)
    return {"status": "revoked", "key_id": key_id, "request_id": rid}


@router.get("/metrics")
async def admin_metrics(
    request: Request,
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    """In-process metrics snapshot (counters, latency percentiles, breakers, cache)."""
    rid = get_or_create_request_id(request)
    if not _admin_ok(x_admin_token):
        return error_response("UNAUTHORIZED", "Admin token required.", 401, rid)
    return {
        "metrics": metrics_svc.snapshot(),
        "circuit_breakers": provider_breakers.status(),
        "verify_cache": verify_cache.stats(),
        "engine": settings.ENGINE_VERSION,
        "environment": settings.ENVIRONMENT,
        "request_id": rid,
    }


# ---- Monetization admin (Phase 1: no payment provider) ----

from pydantic import BaseModel, Field
from typing import Optional as Opt
from app.services.billing import create_account, credit_account_manual, entitlement_summary, attach_key_to_account
from app.services.auth import create_api_key as svc_create_key
from app.models.db import BillingAccount, BillingPlan
from sqlalchemy import select as sa_select


class CreateAccountRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    email: Opt[str] = None
    plan_code: str = Field(default="free", pattern="^(free|starter|pro|enterprise)$")


class CreateAccountKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    environment: str = Field(default="live", pattern="^(live|test)$")
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10000)


class ManualCreditRequest(BaseModel):
    credits: int = Field(..., ge=1, le=10_000_000)
    plan_code: str = Field(default="starter")
    provider_transaction_id: Opt[str] = None
    amount_cents: int = Field(default=0, ge=0)
    note: str = Field(default="manual_credit", max_length=200)


@router.post("/accounts")
async def admin_create_account(
    body: CreateAccountRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    rid = get_or_create_request_id(request)
    if not _admin_ok(x_admin_token):
        return error_response("UNAUTHORIZED", "Admin token required.", 401, rid)
    account, ent = await create_account(db, name=body.name, email=body.email, plan_code=body.plan_code)
    return {
        "account_id": account.id,
        "name": account.name,
        "email": account.email,
        "plan_code": ent.plan_code,
        "credits_remaining": None if ent.unlimited else ent.credits_remaining,
        "unlimited": ent.unlimited,
        "request_id": rid,
    }


@router.post("/accounts/{account_id}/keys")
async def admin_create_account_key(
    account_id: str,
    body: CreateAccountKeyRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    rid = get_or_create_request_id(request)
    if not _admin_ok(x_admin_token):
        return error_response("UNAUTHORIZED", "Admin token required.", 401, rid)
    ar = await db.execute(sa_select(BillingAccount).where(BillingAccount.id == account_id))
    account = ar.scalar_one_or_none()
    if not account:
        return error_response("NOT_FOUND", "Account not found.", 404, rid)
    if settings.is_production and body.environment == "test":
        return error_response("INVALID_REQUEST", "Test keys cannot be created in production.", 400, rid)
    record, full_key = await svc_create_key(
        db,
        name=body.name,
        environment=body.environment,
        rate_limit_per_minute=body.rate_limit_per_minute,
    )
    await attach_key_to_account(db, record, account_id)
    return {
        "account_id": account_id,
        "key_id": record.id,
        "api_key": full_key,
        "environment": body.environment,
        "rate_limit_per_minute": record.rate_limit_per_minute,
        "request_id": rid,
    }


@router.get("/accounts/{account_id}/entitlement")
async def admin_get_entitlement(
    account_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    rid = get_or_create_request_id(request)
    if not _admin_ok(x_admin_token):
        return error_response("UNAUTHORIZED", "Admin token required.", 401, rid)
    summary = await entitlement_summary(db, account_id)
    summary["request_id"] = rid
    return summary


@router.post("/accounts/{account_id}/credits")
async def admin_manual_credit(
    account_id: str,
    body: ManualCreditRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    """Phase 1: credit without payment provider. Idempotent on provider_transaction_id."""
    rid = get_or_create_request_id(request)
    if not _admin_ok(x_admin_token):
        return error_response("UNAUTHORIZED", "Admin token required.", 401, rid)
    try:
        tx = await credit_account_manual(
            db,
            account_id=account_id,
            credits=body.credits,
            plan_code=body.plan_code,
            provider_transaction_id=body.provider_transaction_id,
            amount_cents=body.amount_cents,
            note=body.note,
        )
    except ValueError as e:
        return error_response("INVALID_REQUEST", str(e), 400, rid)
    summary = await entitlement_summary(db, account_id)
    return {
        "transaction_id": tx.id,
        "provider_transaction_id": tx.provider_transaction_id,
        "credits_added": body.credits,
        "entitlement": summary,
        "request_id": rid,
    }


@router.get("/plans")
async def admin_list_plans(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token"),
):
    rid = get_or_create_request_id(request)
    if not _admin_ok(x_admin_token):
        return error_response("UNAUTHORIZED", "Admin token required.", 401, rid)
    r = await db.execute(sa_select(BillingPlan).where(BillingPlan.is_active == True))
    plans = r.scalars().all()
    return {
        "plans": [
            {
                "code": p.code,
                "name": p.name,
                "credits": p.credits,
                "rate_limit_per_minute": p.rate_limit_per_minute,
                "price_cents": p.price_cents,
                "currency": p.currency,
            }
            for p in plans
        ],
        "request_id": rid,
    }
