"""
Database dependencies untuk FastAPI.
Menyediakan database session dan connection management.
"""

from typing import AsyncGenerator
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import SessionLocal
from app.core.config import settings


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency untuk mendapatkan database session.
    Menggunakan async context manager untuk proper cleanup.
    
    Yields:
        AsyncSession: Database session
    """
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_redis() -> AsyncGenerator[redis.Redis, None]:
    """
    Dependency untuk mendapatkan Redis connection.
    
    Yields:
        Redis connection
    """
    redis_client = redis.from_url(
        str(settings.REDIS_URL),
        encoding="utf-8",
        decode_responses=True,
        max_connections=settings.REDIS_POOL_SIZE
    )
    try:
        yield redis_client
    finally:
        await redis_client.close()