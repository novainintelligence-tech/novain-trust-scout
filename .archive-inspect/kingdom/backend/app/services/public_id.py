"""Durable NV-###### public verification IDs via PostgreSQL sequence."""

from __future__ import annotations
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, select
from app.models.db import VerificationPublicIdSequence
from app.config import settings


async def allocate_public_id(db: AsyncSession) -> str:
    """
    Allocate next unique public ID.
    PostgreSQL: nextval('novain_public_id_seq') — concurrent-safe across workers.
    SQLite/dev: single-row counter with immediate flush (weaker under concurrency).
    """
    dialect = db.bind.dialect.name if db.bind else "sqlite"

    if dialect == "postgresql":
        result = await db.execute(text("SELECT nextval('novain_public_id_seq')"))
        n = int(result.scalar_one())
        return f"NV-{n:06d}"

    # Development SQLite path
    result = await db.execute(
        select(VerificationPublicIdSequence).where(VerificationPublicIdSequence.id == 1).with_for_update()
    )
    seq = result.scalar_one_or_none()
    if seq is None:
        seq = VerificationPublicIdSequence(id=1, next_value=1)
        db.add(seq)
        await db.flush()
    current = int(seq.next_value)
    seq.next_value = current + 1
    await db.flush()
    return f"NV-{current:06d}"
