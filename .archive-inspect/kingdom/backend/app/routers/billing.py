"""
Provider-agnostic billing endpoints.

Checkout requires an API key linked to a billing account.
Webhooks are authenticated by provider signature only — never by client payment_status.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.errors import error_response
from app.middleware.auth import get_or_create_request_id, require_api_key
from app.models.db import APIKey
from app.services.payments.base import WebhookRejected
from app.services.payments.checkout import CheckoutError, create_checkout
from app.services.payments.processor import PaymentNotConfirmed, process_webhook

router = APIRouter(prefix="/api/public/v1", tags=["Billing"])


class CheckoutRequest(BaseModel):
    plan_code: str = Field(..., min_length=1, max_length=64)
    # Intentionally ignored if a client sends it — never trust "I paid".
    payment_status: Optional[str] = None


@router.post("/billing/checkout")
async def billing_checkout(
    body: CheckoutRequest,
    request: Request,
    api_key: APIKey = Depends(require_api_key),
    db: AsyncSession = Depends(get_db),
):
    rid = get_or_create_request_id(request)
    if not api_key.account_id:
        return error_response(
            "FORBIDDEN",
            "API key is not linked to a billing account.",
            403,
            rid,
        )
    try:
        result = await create_checkout(
            db,
            account_id=api_key.account_id,
            plan_code=body.plan_code,
        )
    except CheckoutError as e:
        return error_response("PAYMENT_INVALID", e.message, 400, rid)
    result["request_id"] = rid
    return result


@router.post("/webhooks/payments")
async def billing_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    rid = get_or_create_request_id(request)
    body = await request.body()
    headers = {k: v for k, v in request.headers.items()}
    try:
        result = await process_webhook(db, headers=headers, body=body)
    except WebhookRejected as e:
        return error_response("WEBHOOK_REJECTED", str(e), 401, rid)
    except PaymentNotConfirmed as e:
        return error_response("PAYMENT_NOT_CONFIRMED", e.message, 402, rid)
    result["request_id"] = rid
    return result
