"""Production must refuse SQLite."""
from app.config import Settings


def test_production_sqlite_fails_fast():
    s = Settings(
        ENVIRONMENT="production",
        DEBUG=False,
        DATABASE_URL="sqlite+aiosqlite:///./should_fail.db",
        SECRET_KEY="a" * 32,
        ADMIN_TOKEN="b" * 24,
    )
    assert s.is_production and s.is_sqlite
    try:
        s.validate_for_runtime()
        raise AssertionError("expected RuntimeError")
    except RuntimeError as e:
        assert "PostgreSQL" in str(e)
