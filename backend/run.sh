#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
export PYTHONPATH=.
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env — edit ADMIN_TOKEN and SECRET_KEY before production."
fi
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
