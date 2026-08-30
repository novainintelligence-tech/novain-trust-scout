# NOVAIN TRUST — Monetization

## Invariant

```
PAYMENT → ENTITLEMENT → API ACCESS → VERIFICATION
```

Payment never modifies score, evidence, risk gates, or the verification engine.

## Phase 1

- Accounts, plans, entitlements, `payment_transactions`
- Manual / admin credit
- Atomic credit consumption when `BILLING_ENFORCE=true`

## Phase 2 (provider-agnostic core)

Live PSPs are **not** wired. A `PaymentProvider` interface plus a **fake** adapter exist so checkout, signed webhooks, amount checks, and idempotency can be proven without MoonPay/Paystack/Stripe.

```
PaymentProvider
       │
   FakeProvider   ← tests / local only
   (Paystack / MoonPay / Stripe later)
       │
payment_transactions  (expected amount + plan_code)
       │
internal billing_plans.credits
       │
entitlement
```

### Endpoints

| Method | Path | Auth |
|--------|------|------|
| POST | `/api/public/v1/billing/checkout` | Bearer API key linked to an account |
| POST | `/api/public/v1/webhooks/payments` | Provider HMAC signature |

Checkout body: `{ "plan_code": "starter" | "pro" }`

A client field such as `payment_status` is **ignored**. Credits are granted only after a **signed** webhook that matches the server-side pending transaction (account, amount, currency, plan).

### Fake webhook (tests / local)

```
X-Novain-Signature: sha256=<hmac>
X-Novain-Timestamp: <unix>
HMAC-SHA256(PAYMENT_WEBHOOK_SECRET, "{timestamp}.{body}")
```

Duplicate deliveries credit **once** (`credited` flag + unique provider tx id).

### Config

```
PAYMENT_PROVIDER=fake
PAYMENT_WEBHOOK_SECRET=...
PAYMENT_WEBHOOK_MAX_AGE_SECONDS=300
BILLING_ENFORCE=false
BILLING_REQUIRE_ACCOUNT=false
```

`PAYMENT_PROVIDER=fake` is refused in production.

## Plans

| Code | Credits | Rate/min | Price |
|------|---------|----------|-------|
| free | 25 | 10 | $0 (not checkout) |
| starter | 1,000 | 60 | $10 |
| pro | 10,000 | 120 | $49 |
| enterprise | unlimited | 300 | custom (not checkout) |

## Next

Add one live adapter (Paystack, Stripe, or MoonPay) behind `PaymentProvider` without changing verification.
