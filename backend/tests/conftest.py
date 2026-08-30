import os
os.environ.setdefault("NOVAIN_DB_NULL_POOL", "1")
os.environ.setdefault("ENVIRONMENT", "development")
"""Independent DB sessions per test to avoid asyncpg concurrent operation errors."""
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from app.config import settings

settings.ADMIN_TOKEN = "test-admin-token"
settings.ENVIRONMENT = "development"


@pytest_asyncio.fixture
async def client():
    from app.database import init_db
    from app.main import app
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def db_session():
    from app.database import AsyncSessionLocal, init_db
    await init_db()
    async with AsyncSessionLocal() as session:
        yield session
        await session.rollback()
