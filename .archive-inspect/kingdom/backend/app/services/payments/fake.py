"""
Fake payment provider for tests and local development.

NOT a live PSP. Production checkout/webhook MUST refuse this provider.

Webhook contract (test-only):
  Headers:
    X-Novain-Signature: sha256=<hmac_hex>
    X-Novain-Timestamp: <unix seconds>
  Signature input: "{timestamp}.{raw_body}"
  HMAC-SHA256 with PAYMENT_WEBHOOK_SECRET
  Body JSON:
    {
      "event": "payment.confirmed" | "payment.failed" | "payment.cancelled",
      "provider_transaction_id": "...",
      "amount_cents": 1000,
      "currency": "USD",
      "status": "confirmed" | "failed" | "cancelled"
    }
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Mapping
from urllib.parse import quote

from app.config import settings
from app.models.db import generate_uuid
from app.services.payments.base import (
    CheckoutResult,
    PaymentProviderError,
    WebhookEvent,
    WebhookRejected,
)

PROVIDER_NAME = "fake"


def sign_payload(body: bytes, timestamp: str, secret: str) -> str:
    mac = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.".encode("utf-8") + body,
        hashlib.sha256,
    )
    return "sha256=" + mac.hexdigest()


class FakeProvider:
    name = PROVIDER_NAME

    async def create_checkout(
        self,
        *,
        account_id: str,
        plan_code: str,
        amount_cents: int,
        currency: str,
        internal_transaction_id: str,
    ) -> CheckoutResult:
        if settings.is_production:
            raise PaymentProviderError("Fake payment provider is not allowed in production.")
        if amount_cents <= 0:
            raise PaymentProviderError("Checkout amount must be positive.")
        provider_tx = f"fake_{internal_transaction_id.replace('-', '')[:24]}"
        base = (settings.PAYMENT_CHECKOUT_BASE_URL or "https://pay.novain.test").rstrip("/")
        url = f"{base}/checkout/{quote(internal_transaction_id)}"
        return CheckoutResult(
            provider=PROVIDER_NAME,
            provider_transaction_id=provider_tx,
            checkout_url=url,
            checkout_session_id=f"sess_{provider_tx}",
        )

    def verify_webhook(self, headers: Mapping[str, str], body: bytes) -> WebhookEvent:
        if settings.is_production:
            raise WebhookRejected("Fake payment provider is not allowed in production.")

        # Normalize header names
        h = {str(k).lower(): str(v) for k, v in headers.items()}
        signature = h.get("x-novain-signature") or ""
        timestamp = h.get("x-novain-timestamp") or ""
        if not signature or not timestamp:
            raise WebhookRejected("Missing webhook signature or timestamp.")

        try:
            ts = int(timestamp)
        except ValueError as e:
            raise WebhookRejected("Invalid webhook timestamp.") from e

        now = int(time.time())
        max_age = int(getattr(settings, "PAYMENT_WEBHOOK_MAX_AGE_SECONDS", 300) or 300)
        if abs(now - ts) > max_age:
            raise WebhookRejected("Webhook timestamp outside allowed window.")

        secret = settings.PAYMENT_WEBHOOK_SECRET or ""
        expected = sign_payload(body, timestamp, secret)
        if not hmac.compare_digest(expected, signature):
            raise WebhookRejected("Invalid webhook signature.")

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise WebhookRejected("Malformed webhook body.") from e

        if not isinstance(payload, dict):
            raise WebhookRejected("Webhook body must be a JSON object.")

        provider_tx = str(payload.get("provider_transaction_id") or "").strip()
        status = str(payload.get("status") or "").strip().lower()
        event = str(payload.get("event") or "").strip()
        if not provider_tx:
            raise WebhookRejected("Missing provider_transaction_id.")
        if status not in ("confirmed", "failed", "cancelled", "pending"):
            raise WebhookRejected("Unknown payment status.")

        amount = payload.get("amount_cents")
        currency = payload.get("currency")
        amount_cents = int(amount) if amount is not None else None
        currency_s = str(currency).upper() if currency else None

        return WebhookEvent(
            provider=PROVIDER_NAME,
            provider_transaction_id=provider_tx,
            status=status,
            amount_cents=amount_cents,
            currency=currency_s,
            event_type=event or f"payment.{status}",
        )
