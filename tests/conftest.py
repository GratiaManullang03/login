"""
Pytest configuration and fixtures for SecureAuth API tests.
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import AsyncGenerator, Generator, Dict, Any
from uuid import uuid4

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
import fakeredis.aioredis

from app.main import app
from app.db.base import Base
from app.db.session import get_session
from app.core.config import settings
from app.core.security import security
from app.models.user import User
from app.models.session import UserSession
from app.services.user import UserService
from app.services.auth import AuthService
from app.api.dependencies.database import get_db, get_redis


# Test database URL
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://test:test@localhost:5432/secureauth_test"
)

# Override settings for testing
settings.DATABASE_URL = TEST_DATABASE_URL
settings.ENVIRONMENT = "test"
settings.DEBUG = True


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def engine():
    """Create test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=NullPool,  # Disable pooling for tests
    )
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Drop tables after tests
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    TestSessionLocal = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def redis_client():
    """Create a fake Redis client for testing."""
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield client
    await client.close()


@pytest.fixture
def override_dependencies(db_session: AsyncSession, redis_client):
    """Override FastAPI dependencies for testing."""
    async def override_get_db():
        yield db_session
    
    async def override_get_redis():
        yield redis_client
    
    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = override_get_redis
    
    yield
    
    # Clean up
    app.dependency_overrides.clear()


@pytest.fixture
def client(override_dependencies) -> TestClient:
    """Create a test client."""
    return TestClient(app)


@pytest_asyncio.fixture
async def async_client(override_dependencies) -> AsyncGenerator[AsyncClient, None]:
    """Create an async test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create a test user."""
    user_service = UserService(db_session)
    
    user = await user_service.create_user(
        email="test@example.com",
        username="testuser",
        password="TestPassword123!",
        metadata={"test": True}
    )
    
    # Mark as verified
    user.u_is_verified = True
    user.verify_email()
    await db_session.commit()
    
    return user


@pytest_asyncio.fixture
async def test_user_unverified(db_session: AsyncSession) -> User:
    """Create an unverified test user."""
    user_service = UserService(db_session)
    
    user = await user_service.create_user(
        email="unverified@example.com",
        username="unverifieduser",
        password="TestPassword123!",
        metadata={"test": True}
    )
    
    return user


@pytest_asyncio.fixture
async def test_admin_user(db_session: AsyncSession) -> User:
    """Create a test admin user."""
    user_service = UserService(db_session)
    
    user = await user_service.create_user(
        email="admin@example.com",
        username="adminuser",
        password="AdminPassword123!",
        metadata={"test": True, "is_admin": True}
    )
    
    # Mark as verified
    user.u_is_verified = True
    user.verify_email()
    await db_session.commit()
    
    return user


@pytest_asyncio.fixture
async def auth_headers(test_user: User, db_session: AsyncSession) -> Dict[str, str]:
    """Create authentication headers with valid token."""
    auth_service = AuthService(db_session)
    
    # Create session and tokens
    session_data = await auth_service.create_user_session(
        user=test_user,
        ip_address="127.0.0.1",
        user_agent="pytest"
    )
    
    await db_session.commit()
    
    return {
        "Authorization": f"Bearer {session_data['access_token']}"
    }


@pytest_asyncio.fixture
async def admin_auth_headers(test_admin_user: User, db_session: AsyncSession) -> Dict[str, str]:
    """Create authentication headers for admin user."""
    auth_service = AuthService(db_session)
    
    # Create session and tokens
    session_data = await auth_service.create_user_session(
        user=test_admin_user,
        ip_address="127.0.0.1",
        user_agent="pytest"
    )
    
    await db_session.commit()
    
    return {
        "Authorization": f"Bearer {session_data['access_token']}"
    }


@pytest.fixture
def mock_email_service(monkeypatch):
    """Mock email service to prevent actual email sending."""
    sent_emails = []
    
    async def mock_send_email(*args, **kwargs):
        sent_emails.append({
            "args": args,
            "kwargs": kwargs
        })
        return True
    
    monkeypatch.setattr("app.services.email.EmailService.send_email", mock_send_email)
    monkeypatch.setattr("app.services.email.EmailService.send_verification_email", mock_send_email)
    monkeypatch.setattr("app.services.email.EmailService.send_password_reset_email", mock_send_email)
    monkeypatch.setattr("app.services.email.EmailService.send_2fa_enabled_email", mock_send_email)
    
    return sent_emails


@pytest.fixture
def sample_device_info() -> Dict[str, Any]:
    """Sample device information for testing."""
    return {
        "device_id": str(uuid4()),
        "device_name": "Test Device",
        "device_type": "DESKTOP",
        "platform": "WINDOWS",
        "browser": "Chrome",
        "metadata": {
            "screen_resolution": "1920x1080",
            "timezone": "UTC",
            "language": "en-US"
        }
    }


@pytest.fixture
def generate_test_user_data():
    """Factory fixture to generate test user data."""
    def _generate(index: int = 0):
        return {
            "email": f"testuser{index}@example.com",
            "username": f"testuser{index}",
            "password": "TestPassword123!",
            "confirm_password": "TestPassword123!",
            "metadata": {
                "first_name": f"Test{index}",
                "last_name": "User"
            }
        }
    return _generate


# Markers for test categorization
pytest.mark.unit = pytest.mark.unit
pytest.mark.integration = pytest.mark.integration
pytest.mark.security = pytest.mark.security
pytest.mark.slow = pytest.mark.slow
pytest.mark.requires_db = pytest.mark.requires_db
pytest.mark.requires_redis = pytest.mark.requires_redis