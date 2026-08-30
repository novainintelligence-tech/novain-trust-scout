"""
Per-API-key per-minute rate limiting with atomic database counters.
PostgreSQL: INSERT ... ON CONFLICT DO UPDATE RETURNING for concurrency safety.
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from app.models.db import APIKey, APIKeyRateWindow, generate_uuid, utcnow
from app.config import settings
import structlog

logger = structlog.get_logger()


def current_window_start(now: datetime | None = None) -> datetime:
    now = now or utcnow()
    return now.replace(second=0, microsecond=0)


def window_reset_unix(window_start: datetime) -> int:
    end = window_start + timedelta(minutes=1)
    return int(end.timestamp())


class RateLimitExceeded(Exception):
    def __init__(self, limit: int, remaining: int, reset: int):
        self.limit = limit
        self.remaining = remaining
        self.reset = reset
        super().__init__("API rate limit exceeded.")


async def check_and_increment(db: AsyncSession, api_key: APIKey) -> Tuple[int, int, int]:
    """
    Atomically increment usage for current UTC minute.
    Returns (limit, remaining, reset_unix).
    Raises RateLimitExceeded if over limit.
    """
    limit = api_key.rate_limit_per_minute or settings.RATE_LIMIT_PER_MINUTE
    window = current_window_start()
    reset = window_reset_unix(window)
    row_id = generate_uuid()

    dialect = db.bind.dialect.name if db.bind else "sqlite"

    if dialect == "postgresql":
        # Atomic upsert: insert count=1 or increment; return new count
        result = await db.execute(
            text("""
                INSERT INTO api_key_rate_windows (id, api_key_id, window_start, count)
                VALUES (:id, :key_id, :window, 1)
                ON CONFLICT (api_key_id, window_start)
                DO UPDATE SET count = api_key_rate_windows.count + 1
                RETURNING count
            """),
            {"id": row_id, "key_id": api_key.id, "window": window},
        )
        row = result.fetchone()
        new_count = int(row[0]) if row else 1
        await db.commit()
    else:
        # SQLite fallback (dev): select + update with retry
        result = await db.execute(
            select(APIKeyRateWindow).where(
                APIKeyRateWindow.api_key_id == api_key.id,
                APIKeyRateWindow.window_start == window,
            )
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            existing = APIKeyRateWindow(
                id=row_id,
                api_key_id=api_key.id,
                window_start=window,
                count=1,
            )
            db.add(existing)
            try:
                await db.flush()
                new_count = 1
            except Exception:
                await db.rollback()
                result = await db.execute(
                    select(APIKeyRateWindow).where(
                        APIKeyRateWindow.api_key_id == api_key.id,
                        APIKeyRateWindow.window_start == window,
                    )
                )
                existing = result.scalar_one()
                existing.count += 1
                new_count = existing.count
                await db.flush()
        else:
            existing.count += 1
            new_count = existing.count
            await db.flush()
        await db.commit()

    if new_count > limit:
        raise RateLimitExceeded(limit, 0, reset)

    remaining = max(0, limit - new_count)
    return limit, remaining, reset
