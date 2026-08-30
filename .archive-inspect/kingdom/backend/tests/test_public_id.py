import pytest
import asyncio
from app.database import init_db, AsyncSessionLocal
from app.services.public_id import allocate_public_id
from app.config import settings

settings.ENVIRONMENT = "development"


@pytest.mark.asyncio
async def test_public_ids_100_concurrent_unique():
    await init_db()
    sem = asyncio.Semaphore(20)

    async def one():
        async with sem:
            async with AsyncSessionLocal() as db:
                pid = await allocate_public_id(db)
                await db.commit()
                return pid

    ids = await asyncio.gather(*[one() for _ in range(100)])
    assert len(ids) == 100
    assert len(set(ids)) == 100
    assert all(i.startswith("NV-") for i in ids)
