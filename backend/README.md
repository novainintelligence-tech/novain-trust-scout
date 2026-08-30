# NOVAIN TRUST

**Trust and risk intelligence for machine callers.**

Every point of a score maps to a stored evidence record.  
Signals that cannot be observed are returned as **unknown** and are **never scored**.

| | |
|--|--|
| Engine | `novain-risk-2.0` |
| API version | `1.1.0` |
| Production prefix | `/api/public/v1` |

---

## Principles

```
SOURCE → OBSERVATION → EVIDENCE → CHECK → RISK RULE
  → SCORE CONTRIBUTION → RAW SCORE → RISK GATES → FINAL SCORE
```

- Evidence is the source of truth — not the score alone  
- UNKNOWN / UNAVAILABLE contribute **0**  
- Outbound fetches are **SSRF-hardened** (IP pin + redirect re-validation)  
- API secrets are **HMAC-SHA256 hashed** with server pepper; never logged  

---

## Public API

| Method | Path | Auth |
|--------|------|------|
| `POST` | `/api/public/v1/verify/website` | Bearer |
| `POST` | `/api/public/v1/verify/website/batch` | Bearer |
| `GET` | `/api/public/v1/verifications/{id}` | Bearer |
| `GET` | `/api/public/v1/health` | Public |
| `GET` | `/api/public/v1/ready` | Public |
| `GET` | `/api/public/v1/version` | Public |
| `GET` | `/api/public/v1/errors` | Public |
| `GET` | `/api/public/v1/openapi.json` | Public |
| `POST` | `/api/public/v1/billing/checkout` | Bearer (account-linked key) |
| `POST` | `/api/public/v1/webhooks/payments` | Provider HMAC |

### Authentication

```http
Authorization: Bearer nv_live_<key_id>_<secret>
```

- `nv_test_*` rejected when `ENVIRONMENT=production`  
- Revoked → `403 KEY_REVOKED` · Expired → `403 KEY_EXPIRED`  

### Verify

```bash
curl -s "$BASE/api/public/v1/verify/website" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com"}'
```

Agent decision fields: `recommendation`, `risk_gates`, `unknowns`, `evidence[]`, `assessment.*`

**HTTP 200 does not always mean “safe”** — always read `recommendation`.

### Errors

Canonical catalog: `GET /api/public/v1/errors`  
Guide: [docs/AGENT_ERRORS.md](docs/AGENT_ERRORS.md)

429 includes `Retry-After` + `X-RateLimit-*`.

---

## Admin API

Header: `X-Admin-Token: <ADMIN_TOKEN>`

| Method | Path |
|--------|------|
| `POST` | `/api/admin/v1/keys` |
| `GET` | `/api/admin/v1/keys` |
| `POST` | `/api/admin/v1/keys/{key_id}/revoke` |
| `GET` | `/api/admin/v1/metrics` |

---

## Production deploy

See [docs/PRODUCTION.md](docs/PRODUCTION.md).

```bash
export SECRET_KEY="$(openssl rand -hex 32)"
export ADMIN_TOKEN="$(openssl rand -hex 24)"
export POSTGRES_PASSWORD="$(openssl rand -hex 16)"
docker compose up -d --build
curl -fsS http://127.0.0.1:8000/api/public/v1/ready
```

Production **refuses**: SQLite, weak secrets, `DEBUG=true`.

---

## Intelligence sources

| Source | Notes |
|--------|--------|
| HTTP | IP-pinned, redirect-safe |
| TLS | Certificate validity / expiry |
| DNS | A/NS/SPF/DMARC |
| WHOIS | Age, registrar, expiry |
| Content | Contact / privacy / about heuristics |
| Reputation | Safe Browsing*, URLhaus, OpenPhish, VirusTotal* |
| CT | crt.sh presence / depth |

\* Optional API keys — missing → `UNAVAILABLE` (score 0), never invented PASS.

---

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL=postgresql+asyncpg://...
export ENVIRONMENT=development
alembic upgrade head
uvicorn app.main:app --reload
pytest tests/ -q
```

Calibration: `evaluation/run_calibration.py`

---

## Security invariants (do not break)

1. No plaintext API secrets in DB or logs  
2. No score contribution from UNKNOWN/UNAVAILABLE  
3. No outbound connect by hostname after DNS validation (pin IP)  
4. Every non-zero contribution references evidence  
5. Production = PostgreSQL + Alembic + strong secrets  

Engine notes: [docs/ENGINE_CHANGELOG.md](docs/ENGINE_CHANGELOG.md)
