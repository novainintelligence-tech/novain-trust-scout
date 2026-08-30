"""
Database engine and sessions.

Production: PostgreSQL with connection pooling + Alembic only (no create_all).
Development: SQLite or Postgres; create_all allowed for convenience.
Tests: NullPool to avoid asyncpg concurrent-operation issues.
"""
from __future__ import annotations

import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
from app.config import settings
from app.models.db import Base
import structlog

logger = structlog.get_logger()


def validate_production_database() -> None:
    if settings.is_production and settings.is_sqlite:
        raise RuntimeError(
            "Production requires PostgreSQL. SQLite is development-only. "
            "Set DATABASE_URL to postgresql+asyncpg://..."
        )


validate_production_database()


def _build_engine_kwargs() -> dict:
    kwargs: dict = {
        "echo": bool(settings.DEBUG and not settings.is_production),
        "future": True,
        "pool_pre_ping": True,
    }
    # pytest / explicit null pool
    if os.environ.get("NOVAIN_DB_NULL_POOL") == "1" or settings.is_sqlite:
        kwargs["poolclass"] = NullPool
        if settings.is_sqlite:
            kwargs["connect_args"] = {"check_same_thread": False}
        return kwargs

    # Production / staging PostgreSQL pool
    kwargs["pool_size"] = settings.DB_POOL_SIZE
    kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
    kwargs["pool_timeout"] = settings.DB_POOL_TIMEOUT
    kwargs["pool_recycle"] = settings.DB_POOL_RECYCLE
    return kwargs


engine = create_async_engine(settings.DATABASE_URL, **_build_engine_kwargs())

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def init_db() -> None:
    validate_production_database()
    settings.validate_for_runtime()
    if settings.is_production:
        logger.info(
            "production_startup_skip_create_all_use_migrations",
            pool_size=settings.DB_POOL_SIZE,
        )
        return
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info(
        "database_initialized_dev",
        driver="sqlite" if settings.is_sqlite else "postgresql",
    )


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
