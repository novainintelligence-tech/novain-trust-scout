"""Provider-agnostic payment adapters.

PAYMENT → ENTITLEMENT → API ACCESS → VERIFICATION

Live PSPs (Paystack, MoonPay, Stripe) are future adapters behind PaymentProvider.
This package ships a FakeProvider for tests and local development only.
"""
from app.services.payments.base import (
    CheckoutResult,
    PaymentProvider,
    PaymentProviderError,
    WebhookEvent,
    WebhookRejected,
)
from app.services.payments.registry import get_payment_provider

__all__ = [
    "CheckoutResult",
    "PaymentProvider",
    "PaymentProviderError",
    "WebhookEvent",
    "WebhookRejected",
    "get_payment_provider",
]
