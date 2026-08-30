#!/bin/sh
set -eu

echo "[novain] environment=${ENVIRONMENT:-unset}"

if [ "${ENVIRONMENT:-}" = "production" ]; then
  case "${DATABASE_URL:-}" in
    postgresql+asyncpg://*|postgresql://*) ;;
    *)
      echo "[novain] FATAL: production requires DATABASE_URL=postgresql+asyncpg://..." >&2
      exit 1
      ;;
  esac
fi

echo "[novain] running alembic upgrade head"
alembic upgrade head

echo "[novain] starting API"
exec uvicorn app.main:app \
  --host 0.0.0.0 \
  --port "${PORT:-8000}" \
  --workers "${WEB_CONCURRENCY:-2}" \
  --proxy-headers \
  --forwarded-allow-ips="${FORWARDED_ALLOW_IPS:-*}" \
  --log-level "${LOG_LEVEL:-info}" \
  --no-access-log
