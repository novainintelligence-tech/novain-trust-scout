# NOVAIN TRUST — production image
FROM python:3.12-slim AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system novain \
    && useradd --system --gid novain --home-dir /app --shell /usr/sbin/nologin novain

COPY --from=builder /install /usr/local
COPY --chown=novain:novain . .

USER novain

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENVIRONMENT=production \
    PORT=8000 \
    WEB_CONCURRENCY=2 \
    LOG_LEVEL=info

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${PORT}/api/public/v1/ready" || exit 1

ENTRYPOINT ["sh", "scripts/entrypoint.sh"]
