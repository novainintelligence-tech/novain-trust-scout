"""Production configuration fail-closed tests."""
import os
import pytest


def test_production_rejects_weak_secret(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost/db")
    monkeypatch.setenv("SECRET_KEY", "short")
    monkeypatch.setenv("ADMIN_TOKEN", "also-short")
    from importlib import reload
    import app.config as cfg
    with pytest.raises(RuntimeError, match="refused to start"):
        reload(cfg)
        cfg.Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            DATABASE_URL="postgresql+asyncpg://u:p@localhost/db",
            SECRET_KEY="short",
            ADMIN_TOKEN="also-short",
        ).validate_for_runtime()


def test_production_accepts_strong_secrets():
    from app.config import Settings
    s = Settings(
        ENVIRONMENT="production",
        DEBUG=False,
        DATABASE_URL="postgresql+asyncpg://novain:pass@db:5432/novain_trust",
        SECRET_KEY="a" * 32,
        ADMIN_TOKEN="b" * 24,
    )
    s.validate_for_runtime()  # must not raise


def test_production_rejects_sqlite():
    from app.config import Settings
    s = Settings(
        ENVIRONMENT="production",
        DEBUG=False,
        DATABASE_URL="sqlite+aiosqlite:///./x.db",
        SECRET_KEY="a" * 32,
        ADMIN_TOKEN="b" * 24,
    )
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        s.validate_for_runtime()
