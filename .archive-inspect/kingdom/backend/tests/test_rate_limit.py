import pytest
import pytest_asyncio
import asyncio
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.database import init_db, AsyncSessionLocal
from app.services.auth import create_api_key
from app.services.rate_limit import check_and_increment, RateLimitExceeded
from app.config import settings

settings.ADMIN_TOKEN = "test-admin-token"
settings.ENVIRONMENT = "development"


@pytest_asyncio.fixture
async def client():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_rate_limit_sequential(client):
    async with AsyncSessionLocal() as db:
        _, key = await create_api_key(db, name="rl1", environment="test", rate_limit_per_minute=1)
    headers = {"Authorization": f"Bearer {key}"}
    r1 = await client.post("/api/public/v1/verify/website", headers=headers, json={"target": "http://127.0.0.1/"})
    assert r1.status_code != 429
    r2 = await client.post("/api/public/v1/verify/website", headers=headers, json={"target": "http://127.0.0.1/"})
    assert r2.status_code == 429
    assert r2.json()["error"]["code"] == "RATE_LIMITED"


@pytest.mark.asyncio
async def test_rate_limit_concurrent_db():
    """Atomic counter under concurrency (DB level, not ASGI storm)."""
    await init_db()
    async with AsyncSessionLocal() as db:
        rec, _ = await create_api_key(db, name="rlc", environment="test", rate_limit_per_minute=10)

    sem = asyncio.Semaphore(25)
    results = []

    async def one():
        async with sem:
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select
                from app.models.db import APIKey
                r = await db.execute(select(APIKey).where(APIKey.id == rec.id))
                key = r.scalar_one()
                try:
                    await check_and_increment(db, key)
                    return "ok"
                except RateLimitExceeded:
                    return "limited"

    outcomes = await asyncio.gather(*[one() for _ in range(100)])
    ok = outcomes.count("ok")
    limited = outcomes.count("limited")
    assert ok <= 10, ok
    assert limited >= 90, limited
