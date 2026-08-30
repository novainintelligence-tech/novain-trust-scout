"""PaymentProvider protocol — adapters implement this; billing never talks to a PSP directly."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Protocol


class PaymentProviderError(Exception):
    """Provider could not create or confirm a payment. Fail closed — no credits."""


class WebhookRejected(Exception):
    """Signature, timestamp, or payload failed verification. Fail closed — no credits."""


@dataclass(frozen=True)
class CheckoutResult:
    provider: str
    provider_transaction_id: str
    checkout_url: str
    checkout_session_id: Optional[str] = None


@dataclass(frozen=True)
class WebhookEvent:
    provider: str
    provider_transaction_id: str
    status: str  # confirmed | failed | cancelled | pending
    amount_cents: Optional[int] = None
    currency: Optional[str] = None
    event_type: Optional[str] = None


class PaymentProvider(Protocol):
    name: str

    async def create_checkout(
        self,
        *,
        account_id: str,
        plan_code: str,
        amount_cents: int,
        currency: str,
        internal_transaction_id: str,
    ) -> CheckoutResult:
        """Initialize a payment with the provider. Never trusts client payment_status."""
        ...

    def verify_webhook(
        self,
        headers: Mapping[str, str],
        body: bytes,
    ) -> WebhookEvent:
        """Verify signature and parse event. Raise WebhookRejected on any failure."""
        ...
