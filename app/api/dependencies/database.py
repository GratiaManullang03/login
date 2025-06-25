"""
Database dependencies untuk FastAPI.
Menyediakan database session dan connection management.
"""

from typing import AsyncGenerator, Optional
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
        finally:
            await session.close()


# Redis connection pool (singleton)
_redis_pool: Optional[redis.ConnectionPool] = None


async def get_redis_pool() -> redis.ConnectionPool:
    """
    Get or create Redis connection pool.
    
    Returns:
        Redis connection pool
    """
    global _redis_pool
    
    if _redis_pool is None:
        _redis_pool = redis.ConnectionPool.from_url(
            settings.REDIS_URL,
            max_connections=settings.REDIS_POOL_SIZE,
            decode_responses=True
        )
    
    return _redis_pool


async def get_redis() -> AsyncGenerator[redis.Redis, None]:
    """
    Dependency untuk mendapatkan Redis connection.
    
    Yields:
        Redis connection
    """
    pool = await get_redis_pool()
    redis_client = redis.Redis(connection_pool=pool)
    
    try:
        yield redis_client
    finally:
        await redis_client.close()


async def close_redis_pool():
    """
    Close Redis connection pool.
    Should be called on application shutdown.
    """
    global _redis_pool
    
    if _redis_pool:
        await _redis_pool.disconnect()
        _redis_pool = None