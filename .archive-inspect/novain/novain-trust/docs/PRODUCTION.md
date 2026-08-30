# NOVAIN TRUST — Production deployment

## Requirements

- PostgreSQL 16+
- Python 3.12+ or Docker
- Strong secrets (never use compose defaults)

```bash
export SECRET_KEY="$(openssl rand -hex 32)"
export ADMIN_TOKEN="$(openssl rand -hex 24)"
export POSTGRES_PASSWORD="$(openssl rand -hex 16)"
```

## Docker Compose

```bash
cp .env.example .env
# fill SECRET_KEY, ADMIN_TOKEN, POSTGRES_PASSWORD

docker compose up -d --build
curl -fsS http://127.0.0.1:8000/api/public/v1/ready
curl -fsS http://127.0.0.1:8000/api/public/v1/health
```

Entrypoint always runs `alembic upgrade head` before serving.

## Create a live API key

```bash
curl -s http://127.0.0.1:8000/api/admin/v1/keys \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"prod-agent","environment":"live","rate_limit_per_minute":120}'
```

Store the returned `api_key` once. Only the hash is retained.

## Security invariants

- `ENVIRONMENT=production` refuses SQLite and weak secrets
- Docs disabled unless `ENABLE_DOCS=true`
- API secrets never logged
- Outbound fetches are IP-pinned (SSRF)
- UNKNOWN / UNAVAILABLE contribute 0 to scores

## Optional reputation keys

```bash
GOOGLE_SAFE_BROWSING_API_KEY=...
VIRUSTOTAL_API_KEY=...
```

Without keys, those signals are `UNAVAILABLE` (honest zero contribution). URLhaus and OpenPhish still run when enabled.


## API key hashing

Secrets are stored as **HMAC-SHA256(SECRET_KEY, secret)**.

If you rotate `SECRET_KEY`, existing API keys become invalid — re-issue keys after a secret rotation.
