"""
Tests for authentication endpoints and functionality.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock

from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import security
from app.models.user import User
from app.models.session import UserSession
from app.services.auth import AuthService
from app.services.two_factor import TwoFactorService
from app.core.exceptions import (
    InvalidCredentialsException,
    AccountLockedException,
    EmailNotVerifiedException
)


@pytest.mark.asyncio
@pytest.mark.integration
class TestLogin:
    """Test login endpoint."""
    
    async def test_login_success(
        self,
        async_client: AsyncClient,
        test_user: User,
        mock_email_service
    ):
        """Test successful login with valid credentials."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/login",
            data={
                "username": test_user.u_email,  # OAuth2 form uses 'username' field
                "password": "TestPassword123!"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["id"] == str(test_user.u_id)
        assert data["requires_2fa"] is False
    
    async def test_login_with_username(
        self,
        async_client: AsyncClient,
        test_user: User,
        mock_email_service
    ):
        """Test login using username instead of email."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/login",
            data={
                "username": test_user.u_username,  # Using username
                "password": "TestPassword123!"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["user"]["username"] == test_user.u_username
    
    async def test_login_invalid_credentials(
        self,
        async_client: AsyncClient,
        test_user: User
    ):
        """Test login with invalid password."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/login",
            data={
                "username": test_user.u_email,
                "password": "WrongPassword123!"
            }
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Invalid credentials"
    
    async def test_login_non_existent_user(
        self,
        async_client: AsyncClient
    ):
        """Test login with non-existent user."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/login",
            data={
                "username": "nonexistent@example.com",
                "password": "AnyPassword123!"
            }
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == "Invalid credentials"
    
    async def test_login_unverified_email(
        self,
        async_client: AsyncClient,
        test_user_unverified: User
    ):
        """Test login with unverified email."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/login",
            data={
                "username": test_user_unverified.u_email,
                "password": "TestPassword123!"
            }
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert response.json()["detail"] == "Email not verified"
    
    async def test_login_locked_account(
        self,
        async_client: AsyncClient,
        test_user: User,
        db_session: AsyncSession
    ):
        """Test login with locked account."""
        # Lock the account
        test_user.u_is_locked = True
        test_user.u_locked_until = datetime.now(timezone.utc) + timedelta(hours=1)
        await db_session.commit()
        
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/login",
            data={
                "username": test_user.u_email,
                "password": "TestPassword123!"
            }
        )
        
        assert response.status_code == status.HTTP_423_LOCKED
        assert "Account is locked" in response.json()["detail"]
    
    async def test_login_with_device_info(
        self,
        async_client: AsyncClient,
        test_user: User,
        sample_device_info: dict,
        mock_email_service
    ):
        """Test login with device information."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/login",
            data={
                "username": test_user.u_email,
                "password": "TestPassword123!"
            },
            json={"device_info": sample_device_info}  # Send as JSON body
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "device_id" in data
    
    async def test_login_rate_limit(
        self,
        async_client: AsyncClient,
        test_user: User
    ):
        """Test login rate limiting."""
        # Make multiple failed login attempts
        for i in range(settings.LOGIN_RATE_LIMIT_PER_MINUTE + 1):
            response = await async_client.post(
                f"{settings.API_V1_STR}/auth/login",
                data={
                    "username": test_user.u_email,
                    "password": "WrongPassword!"
                }
            )
            
            if i < settings.LOGIN_RATE_LIMIT_PER_MINUTE:
                assert response.status_code == status.HTTP_401_UNAUTHORIZED
            else:
                # Should be rate limited
                assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    
    @pytest.mark.skip(reason="2FA implementation pending")
    async def test_login_with_2fa_enabled(
        self,
        async_client: AsyncClient,
        test_user: User,
        db_session: AsyncSession
    ):
        """Test login when 2FA is enabled."""
        # Enable 2FA for user
        two_fa_service = TwoFactorService(db_session)
        await two_fa_service.setup_2fa(test_user.u_id)
        
        # Mock 2FA as enabled
        with patch.object(User, 'has_2fa_enabled', return_value=True):
            # First login attempt should require 2FA
            response = await async_client.post(
                f"{settings.API_V1_STR}/auth/login",
                data={
                    "username": test_user.u_email,
                    "password": "TestPassword123!"
                }
            )
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            assert response.json()["detail"] == "Two-factor authentication required"
            
            # Should have session_id for 2FA verification
            assert "session_id" in response.json()


@pytest.mark.asyncio
@pytest.mark.integration
class TestRefreshToken:
    """Test refresh token endpoint."""
    
    async def test_refresh_token_success(
        self,
        async_client: AsyncClient,
        test_user: User,
        auth_headers: dict
    ):
        """Test successful token refresh."""
        # First login to get tokens
        login_response = await async_client.post(
            f"{settings.API_V1_STR}/auth/login",
            data={
                "username": test_user.u_email,
                "password": "TestPassword123!"
            }
        )
        
        refresh_token = login_response.json()["refresh_token"]
        
        # Refresh the token
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    async def test_refresh_token_invalid(
        self,
        async_client: AsyncClient
    ):
        """Test refresh with invalid token."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/refresh",
            json={"refresh_token": "invalid-refresh-token"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid refresh token" in response.json()["detail"]
    
    async def test_refresh_token_expired(
        self,
        async_client: AsyncClient,
        test_user: User
    ):
        """Test refresh with expired token."""
        # Create an expired token
        with patch("app.core.config.settings.REFRESH_TOKEN_EXPIRE_DAYS", -1):
            login_response = await async_client.post(
                f"{settings.API_V1_STR}/auth/login",
                data={
                    "username": test_user.u_email,
                    "password": "TestPassword123!"
                }
            )
            
            refresh_token = login_response.json()["refresh_token"]
        
        # Try to refresh
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Token has expired" in response.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestLogout:
    """Test logout endpoint."""
    
    async def test_logout_success(
        self,
        async_client: AsyncClient,
        test_user: User,
        auth_headers: dict
    ):
        """Test successful logout."""
        # First login
        login_response = await async_client.post(
            f"{settings.API_V1_STR}/auth/login",
            data={
                "username": test_user.u_email,
                "password": "TestPassword123!"
            }
        )
        
        refresh_token = login_response.json()["refresh_token"]
        
        # Logout
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/logout",
            json={"refresh_token": refresh_token},
            headers=auth_headers
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["message"] == "Successfully logged out"
        
        # Verify token is invalid after logout
        refresh_response = await async_client.post(
            f"{settings.API_V1_STR}/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert refresh_response.status_code == status.HTTP_401_UNAUTHORIZED
    
    async def test_logout_all_sessions(
        self,
        async_client: AsyncClient,
        test_user: User,
        auth_headers: dict
    ):
        """Test logout from all sessions."""
        # Create multiple sessions
        for i in range(3):
            await async_client.post(
                f"{settings.API_V1_STR}/auth/login",
                data={
                    "username": test_user.u_email,
                    "password": "TestPassword123!"
                }
            )
        
        # Logout all
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/logout",
            json={"all_sessions": True},
            headers=auth_headers
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert "all sessions" in response.json()["message"]
    
    async def test_logout_without_auth(
        self,
        async_client: AsyncClient
    ):
        """Test logout without authentication."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/logout",
            json={"refresh_token": "some-token"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.integration
class TestCSRF:
    """Test CSRF protection."""
    
    async def test_get_csrf_token(
        self,
        async_client: AsyncClient
    ):
        """Test getting CSRF token."""
        response = await async_client.get(
            f"{settings.API_V1_STR}/auth/csrf-token"
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "csrf_token" in data
    
    async def test_post_without_csrf_token(
        self,
        async_client: AsyncClient,
        test_user: User
    ):
        """Test POST request without CSRF token."""
        # This should fail for endpoints that require CSRF
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/profile",
            json={"full_name": "Updated Name"},
            headers={"Authorization": "Bearer fake-token"}
        )
        
        # Should get CSRF error or auth error
        assert response.status_code in [status.HTTP_403_FORBIDDEN, status.HTTP_401_UNAUTHORIZED]


@pytest.mark.asyncio
@pytest.mark.unit
class TestAuthService:
    """Test AuthService unit tests."""
    
    async def test_validate_session_token_expired(
        self,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test validating expired session."""
        auth_service = AuthService(db_session)
        
        # Create session with expired token
        with patch("app.core.config.settings.ACCESS_TOKEN_EXPIRE_MINUTES", -1):
            session_data = await auth_service.create_user_session(
                user=test_user,
                ip_address="127.0.0.1"
            )
        
        # Validate should fail
        with pytest.raises(InvalidCredentialsException):
            await auth_service.validate_session(
                session_data["access_token"]
            )
    
    async def test_track_login_attempt(
        self,
        db_session: AsyncSession,
        test_user: User
    ):
        """Test tracking login attempts."""
        auth_service = AuthService(db_session)
        
        # Track failed attempts
        for i in range(settings.MAX_LOGIN_ATTEMPTS - 1):
            await auth_service.track_login_attempt(
                identifier=test_user.u_email,
                success=False,
                ip_address="127.0.0.1"
            )
        
        # User should not be locked yet
        await db_session.refresh(test_user)
        assert test_user.u_is_locked is False
        
        # One more failed attempt should lock
        await auth_service.track_login_attempt(
            identifier=test_user.u_email,
            success=False,
            ip_address="127.0.0.1"
        )
        
        await db_session.refresh(test_user)
        assert test_user.u_is_locked is True