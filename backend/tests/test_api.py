import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.database import init_db, AsyncSessionLocal
from app.services.auth import create_api_key
from app.config import settings

settings.ADMIN_TOKEN = "test-admin-token"
settings.ENVIRONMENT = "development"


@pytest_asyncio.fixture
async def client():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def api_key():
    await init_db()
    async with AsyncSessionLocal() as db:
        _, full = await create_api_key(db, name="test", environment="test", rate_limit_per_minute=100)
        return full


@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/api/public/v1/health")
    assert r.status_code == 200
    assert r.json()["engine"] == "novain-risk-2.0"
    assert "whois" in r.json()["sources"]


@pytest.mark.asyncio
async def test_ssrf_target_blocked_code(client, api_key):
    r = await client.post(
        "/api/public/v1/verify/website",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"target": "http://127.0.0.1/"},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "TARGET_BLOCKED"


@pytest.mark.asyncio
async def test_unauthorized(client):
    r = await client.post("/api/public/v1/verify/website", json={"target": "https://example.com"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_admin_create_key(client):
    r = await client.post(
        "/api/admin/v1/keys",
        headers={"X-Admin-Token": "test-admin-token"},
        json={"name": "agent", "environment": "test"},
    )
    assert r.status_code == 200
    assert r.json()["api_key"].startswith("nv_test_")
