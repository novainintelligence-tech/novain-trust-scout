import pytest
import pytest_asyncio
from datetime import timedelta
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.database import init_db, AsyncSessionLocal
from app.services.auth import create_api_key, revoke_key, authenticate
from app.models.db import utcnow
from app.config import settings

settings.ADMIN_TOKEN = "test-admin-token"
settings.ENVIRONMENT = "development"


@pytest_asyncio.fixture
async def client():
    settings.ENVIRONMENT = "development"
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_missing_token(client):
    r = await client.post("/api/public/v1/verify/website", json={"target": "https://example.com"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_revoked_key(client):
    async with AsyncSessionLocal() as db:
        rec, key = await create_api_key(db, name="rev", environment="test")
        await revoke_key(db, rec.id)
    r = await client.post(
        "/api/public/v1/verify/website",
        headers={"Authorization": f"Bearer {key}"},
        json={"target": "https://example.com"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "KEY_REVOKED"


@pytest.mark.asyncio
async def test_expired_key(client):
    async with AsyncSessionLocal() as db:
        rec, key = await create_api_key(db, name="exp", environment="test", expires_days=1)
        rec.expires_at = utcnow() - timedelta(days=1)
        await db.commit()
    r = await client.post(
        "/api/public/v1/verify/website",
        headers={"Authorization": f"Bearer {key}"},
        json={"target": "https://example.com"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "KEY_EXPIRED"


@pytest.mark.asyncio
async def test_test_key_rejected_in_production():
    """Unit-level: authenticate rejects nv_test when ENVIRONMENT=production."""
    prev = settings.ENVIRONMENT
    settings.ENVIRONMENT = "production"
    try:
        if settings.is_sqlite:
            pytest.skip("cannot run production auth test with sqlite URL")
        async with AsyncSessionLocal() as db:
            # create while temporarily in development for insert
            settings.ENVIRONMENT = "development"
            _, key = await create_api_key(db, name="tprod", environment="test")
            settings.ENVIRONMENT = "production"
            k, err = await authenticate(db, f"Bearer {key}")
            assert k is None
            assert err == "UNAUTHORIZED"
    finally:
        settings.ENVIRONMENT = prev
