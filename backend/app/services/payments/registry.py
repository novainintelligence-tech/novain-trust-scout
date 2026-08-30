"""Resolve the configured payment provider. Live PSPs are not registered yet."""
from __future__ import annotations

from app.config import settings
from app.services.payments.base import PaymentProvider, PaymentProviderError
from app.services.payments.fake import FakeProvider


def get_payment_provider(name: str | None = None) -> PaymentProvider:
    chosen = (name or settings.PAYMENT_PROVIDER or "fake").strip().lower()
    if chosen == "fake":
        return FakeProvider()
    raise PaymentProviderError(
        f"Payment provider '{chosen}' is not configured. "
        "Phase 2 ships a provider-agnostic core with the fake adapter only."
    )
