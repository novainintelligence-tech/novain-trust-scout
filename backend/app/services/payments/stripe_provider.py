from __future__ import annotations

from typing import Any, Mapping

import stripe
from stripe import StripeClient

from app.config import settings
from app.services.payments.base import CheckoutResult, PaymentProviderError, WebhookEvent, WebhookRejected


class StripeProvider:
    name = "stripe"

    def __init__(self) -> None:
        if not settings.STRIPE_SECRET_KEY:
            raise PaymentProviderError("STRIPE_SECRET_KEY is not configured.")
        self.client = StripeClient(settings.STRIPE_SECRET_KEY)

    async def create_checkout(
        self, *, account_id: str, plan_code: str, amount_cents: int, currency: str, internal_transaction_id: str
    ) -> CheckoutResult:
        if amount_cents <= 0:
            raise PaymentProviderError("Checkout amount must be positive.")
        try:
            session = await self.client.v1.checkout.sessions.create_async({
                "mode": "payment",
                "line_items": [{"price_data": {"currency": currency.lower(), "product_data": {"name": f"NOVAIN Trust {plan_code.title()} credits"}, "unit_amount": amount_cents}, "quantity": 1}],
                "success_url": settings.STRIPE_SUCCESS_URL,
                "cancel_url": settings.STRIPE_CANCEL_URL,
                "client_reference_id": account_id,
                "metadata": {"account_id": account_id, "plan_code": plan_code, "transaction_id": internal_transaction_id},
                "integration_identifier": "novain_trust_" + internal_transaction_id.replace("-", "")[:8],
            })
        except Exception as exc:
            raise PaymentProviderError(f"Stripe checkout creation failed: {exc}") from exc
        if not session.url or not session.id:
            raise PaymentProviderError("Stripe returned an incomplete checkout session.")
        return CheckoutResult("stripe", session.payment_intent or session.id, session.url, session.id)

    def verify_webhook(self, headers: Mapping[str, str], body: bytes) -> WebhookEvent:
        secret = settings.STRIPE_WEBHOOK_SECRET
        if not secret:
            raise WebhookRejected("STRIPE_WEBHOOK_SECRET is not configured.")
        signature = next((v for k, v in headers.items() if k.lower() == "stripe-signature"), "")
        if not signature:
            raise WebhookRejected("Missing Stripe webhook signature.")
        try:
            event = stripe.Webhook.construct_event(body, signature, secret)
        except Exception as exc:
            raise WebhookRejected("Invalid Stripe webhook signature or payload.") from exc
        obj: Any = event.get("data", {}).get("object", {})
        metadata = obj.get("metadata", {}) or {}
        tx_id = metadata.get("transaction_id") or obj.get("payment_intent") or obj.get("id")
        event_type = event.get("type", "")
        status = "confirmed" if event_type in ("checkout.session.completed", "checkout.session.async_payment_succeeded") and obj.get("payment_status") != "unpaid" else "failed" if event_type == "checkout.session.async_payment_failed" else "pending"
        return WebhookEvent("stripe", str(tx_id), status, obj.get("amount_total"), str(obj.get("currency") or "").upper() or None, event_type)
