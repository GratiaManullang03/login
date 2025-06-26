"""
Database session management untuk SecureAuth API.
Menggunakan SQLAlchemy dengan async support.
"""

from typing import AsyncGenerator, Optional
import logging
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker
)
from sqlalchemy.pool import NullPool, AsyncAdaptedQueuePool
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import event, exc, select, text

from app.core.config import settings

logger = logging.getLogger(__name__)


def create_engine() -> AsyncEngine:
    """
    Create async SQLAlchemy engine dengan konfigurasi optimal.
    
    Returns:
        Configured AsyncEngine
    """
    # Engine arguments
    engine_args = {
        "echo": settings.DEBUG,  # SQL logging saat debug
        "future": True,  # Use SQLAlchemy 2.0 style
        "pool_pre_ping": settings.DB_POOL_PRE_PING,  # Test connections
    }
    
    # Configure connection pool based on environment
    if settings.ENVIRONMENT == "test":
        # Use NullPool for testing to avoid connection issues
        engine_args["poolclass"] = NullPool
    else:
        # Production pool configuration
        engine_args["pool_size"] = settings.DB_POOL_SIZE
        engine_args["max_overflow"] = settings.DB_MAX_OVERFLOW
        engine_args["pool_timeout"] = 30  # 30 seconds timeout
        engine_args["pool_recycle"] = 3600  # Recycle connections after 1 hour
        
        # Additional performance settings
        engine_args["connect_args"] = {
            "server_settings": {
                "application_name": settings.APP_NAME,
                "jit": "off",  # Disable JIT for consistent performance
            },
            "command_timeout": 60,
            "prepared_statement_cache_size": 0,  # Disable to avoid issues
        }
    
    # Create engine
    engine = create_async_engine(
        str(settings.DATABASE_URL),
        **engine_args
    )
    
    # Add event listeners for connection debugging if needed
    if settings.DEBUG:
        @event.listens_for(engine.sync_engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            """Log new connections."""
            logger.debug(f"New database connection established: {connection_record}")
        
        @event.listens_for(engine.sync_engine, "checkout")
        def receive_checkout(dbapi_connection, connection_record, connection_proxy):
            """Log connection checkouts from pool."""
            logger.debug(f"Connection checked out from pool: {connection_record}")
    
    return engine


# Create global engine instance
engine = create_engine()

# Create session factory
SessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,  # Don't expire objects after commit
    autocommit=False,
    autoflush=False,  # Manual flush for better control
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Get database session.
    Alternatif untuk dependency injection.
    
    Yields:
        AsyncSession instance
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


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager untuk database session.
    Useful untuk non-FastAPI contexts.
    
    Example:
        async with get_db_context() as db:
            # Use db session
            pass
    """
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """
    Initialize database.
    - Test connection
    - Create tables (jika menggunakan Base.metadata.create_all)
    - Run any initialization logic
    """
    try:
        # Test connection
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
            logger.info("Database connection successful")
            
            # Optional: Create tables (biasanya pakai Alembic)
            # from app.db.base import Base
            # await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database initialized successfully")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


async def close_db() -> None:
    """
    Close database connections.
    Should be called on application shutdown.
    """
    await engine.dispose()
    logger.info("Database connections closed")


class DatabaseSessionManager:
    """
    Database session manager untuk advanced use cases.
    Provides transaction management dan session lifecycle control.
    """
    
    def __init__(self):
        self._session: Optional[AsyncSession] = None
    
    async def __aenter__(self) -> AsyncSession:
        """Enter async context."""
        self._session = SessionLocal()
        return self._session
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context dengan proper cleanup."""
        if self._session:
            try:
                if exc_type:
                    await self._session.rollback()
                else:
                    await self._session.commit()
            except Exception:
                await self._session.rollback()
                raise
            finally:
                await self._session.close()
                self._session = None
    
    @asynccontextmanager
    async def begin(self):
        """
        Begin explicit transaction.
        
        Example:
            async with manager.begin():
                # All operations in transaction
                pass
        """
        if not self._session:
            raise RuntimeError("Session not initialized")
        
        async with self._session.begin():
            yield self._session
    
    async def commit(self):
        """Manually commit transaction."""
        if self._session:
            await self._session.commit()
    
    async def rollback(self):
        """Manually rollback transaction."""
        if self._session:
            await self._session.rollback()
    
    async def close(self):
        """Close session."""
        if self._session:
            await self._session.close()
            self._session = None


# Health check query untuk monitoring
async def check_database_health() -> dict:
    """
    Check database health dan return metrics.
    
    Returns:
        Dictionary dengan health metrics
    """
    health_info = {
        "connected": False,
        "pool_size": engine.pool.size() if hasattr(engine.pool, 'size') else None,
        "checked_out_connections": engine.pool.checked_out() if hasattr(engine.pool, 'checked_out') else None,
        "overflow": engine.pool.overflow() if hasattr(engine.pool, 'overflow') else None,
        "response_time_ms": None,
        "error": None
    }
    
    try:
        import time
        start_time = time.time()
        
        async with SessionLocal() as session:
            # Simple query untuk test
            result = await session.execute(text("SELECT 1"))
            result.scalar()
        
        response_time = (time.time() - start_time) * 1000  # Convert to ms
        
        health_info["connected"] = True
        health_info["response_time_ms"] = round(response_time, 2)
        
    except Exception as e:
        health_info["error"] = str(e)
        logger.error(f"Database health check failed: {e}")
    
    return health_info