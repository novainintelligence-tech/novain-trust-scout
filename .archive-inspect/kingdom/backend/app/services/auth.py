"""
API key authentication for NOVAIN TRUST.

Canonical form: Authorization: Bearer nv_live_<key_id>_<secret>
Only the secret is hashed (HMAC-SHA256 with SECRET_KEY as pepper) and stored.
key_id is used for efficient lookup. Production rejects nv_test_* keys.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.db import APIKey, APIUsage, utcnow
import structlog

logger = structlog.get_logger()


def hash_secret(secret: str) -> str:
    """Peppered HMAC-SHA256 — never store plaintext secrets."""
    pepper = (settings.SECRET_KEY or "").encode("utf-8")
    return hmac.new(pepper, secret.encode("utf-8"), hashlib.sha256).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    if a is None or b is None:
        return False
    return hmac.compare_digest(str(a), str(b))


def generate_key_material(environment: str = "live") -> Tuple[str, str, str]:
    prefix = "nv_live_" if environment == "live" else "nv_test_"
    key_id = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    full = f"{prefix}{key_id}_{secret}"
    return key_id, secret, full


def parse_bearer_token(token: str) -> Optional[Tuple[str, str, str]]:
    if not token:
        return None
    token = token.strip()
    for prefix in ("nv_live_", "nv_test_"):
        if token.startswith(prefix):
            rest = token[len(prefix) :]
            if "_" not in rest:
                return None
            key_id, secret = rest.split("_", 1)
            if not key_id or not secret:
                return None
            return prefix, key_id, secret
    return None


async def create_api_key(
    db: AsyncSession,
    name: str,
    owner_email: Optional[str] = None,
    environment: str = "live",
    rate_limit_per_minute: int = 60,
    expires_days: Optional[int] = None,
) -> Tuple[APIKey, str]:
    env = "live" if environment == "live" else "test"
    key_id, secret, full_key = generate_key_material(env)
    expires_at = None
    if expires_days:
        expires_at = utcnow() + timedelta(days=expires_days)

    record = APIKey(
        id=key_id,
        key_prefix="nv_live_" if env == "live" else "nv_test_",
        environment=env,
        secret_hash=hash_secret(secret),
        name=name,
        owner_email=owner_email,
        is_active=True,
        is_revoked=False,
        expires_at=expires_at,
        rate_limit_per_minute=rate_limit_per_minute,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    logger.info("api_key_created", key_id=key_id, environment=env)
    return record, full_key


async def authenticate(db: AsyncSession, authorization: Optional[str]) -> Tuple[Optional[APIKey], Optional[str]]:
    """
    Returns (api_key, error_code).
    error_code: UNAUTHORIZED | KEY_REVOKED | KEY_EXPIRED
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        return None, "UNAUTHORIZED"
    token = authorization[7:].strip()
    parsed = parse_bearer_token(token)
    if not parsed:
        return None, "UNAUTHORIZED"
    prefix, key_id, secret = parsed

    if settings.is_production and prefix == "nv_test_":
        return None, "UNAUTHORIZED"

    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    record = result.scalar_one_or_none()
    if not record:
        return None, "UNAUTHORIZED"

    if record.key_prefix != prefix:
        return None, "UNAUTHORIZED"

    if not constant_time_compare(record.secret_hash, hash_secret(secret)):
        return None, "UNAUTHORIZED"

    if record.is_revoked or not record.is_active:
        return None, "KEY_REVOKED"

    if record.expires_at is not None:
        exp = record.expires_at
        if exp.tzinfo is None:
            from datetime import timezone
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < utcnow():
            return None, "KEY_EXPIRED"

    # Environment isolation: live keys only in production; test keys only outside production
    if settings.is_production and record.environment != "live":
        return None, "UNAUTHORIZED"
    if not settings.is_production and record.environment == "live" and settings.ENVIRONMENT.lower() == "test":
        # allow live keys in development for convenience; reject only in explicit test env if desired
        pass

    record.last_used_at = utcnow()
    record.request_count = (record.request_count or 0) + 1
    await db.commit()
    return record, None


async def revoke_key(db: AsyncSession, key_id: str) -> bool:
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    record = result.scalar_one_or_none()
    if not record:
        return False
    record.is_revoked = True
    record.is_active = False
    await db.commit()
    logger.info("api_key_revoked", key_id=key_id)
    return True


async def record_usage(
    db: AsyncSession,
    api_key: APIKey,
    request_id: str,
    endpoint: str,
    status_code: int,
    latency_ms: float = 0.0,
    verification_id: Optional[str] = None,
) -> None:
    try:
        usage = APIUsage(
            request_id=request_id,
            api_key_id=api_key.id,
            endpoint=endpoint,
            verification_id=verification_id,
            status_code=status_code,
            latency_ms=latency_ms,
            units=1,
        )
        db.add(usage)
        await db.commit()
    except Exception:
        logger.warning("usage_record_failed", request_id=request_id)
        try:
            await db.rollback()
        except Exception:
            pass
