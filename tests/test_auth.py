"""
Tests for authentication endpoints and functionality.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock

from fastapi import status
from httpx import AsyncClient

from app.core.config import settings
from app.core.security import security
from app.models.user import User
from app.models.session import UserSession
from app.services.auth import AuthService
from app.services.two_factor import TwoFactorService


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
        assert data["user_id"] == str(test_user.u_id)
        assert data["requires_2fa"] is False
    
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
        assert "Invalid email or password" in response.json()["detail"]
    
    async def test_login_nonexistent_user(self, async_client: AsyncClient):
        """Test login with non-existent email."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/login",
            data={
                "username": "nonexistent@example.com",
                "password": "Password123!"
            }
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid email or password" in response.json()["detail"]
    
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
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Email not verified" in response.json()["detail"]
    
    async def test_login_account_locked(
        self,
        async_client: AsyncClient,
        test_user: User,
        db_session
    ):
        """Test login with locked account."""
        # Lock the account
        test_user.lock_account(
            datetime.now(timezone.utc) + timedelta(minutes=30)
        )
        await db_session.commit()
        
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/login",
            data={
                "username": test_user.u_email,
                "password": "TestPassword123!"
            }
        )
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "Account is locked" in response.json()["detail"]
    
    async def test_login_rate_limit(
        self,
        async_client: AsyncClient,
        test_user: User
    ):
        """Test login rate limiting."""
        # Make multiple failed login attempts
        for _ in range(settings.LOGIN_RATE_LIMIT_PER_MINUTE + 1):
            response = await async_client.post(
                f"{settings.API_V1_STR}/auth/login",
                data={
                    "username": test_user.u_email,
                    "password": "WrongPassword"
                }
            )
        
        # The last request should be rate limited
        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    
    async def test_login_with_device_info(
        self,
        async_client: AsyncClient,
        test_user: User,
        sample_device_info
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


@pytest.mark.asyncio
@pytest.mark.integration
class TestLogout:
    """Test logout endpoint."""
    
    async def test_logout_success(
        self,
        async_client: AsyncClient,
        auth_headers: dict
    ):
        """Test successful logout."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/logout",
            headers=auth_headers
        )
        
        assert response.status_code == status.HTTP_204_NO_CONTENT
    
    async def test_logout_all_sessions(
        self,
        async_client: AsyncClient,
        auth_headers: dict,
        test_user: User,
        db_session
    ):
        """Test logout from all sessions."""
        # Create multiple sessions
        auth_service = AuthService(db_session)
        for _ in range(3):
            await auth_service.create_user_session(
                user=test_user,
                ip_address="127.0.0.1",
                user_agent="pytest"
            )
        await db_session.commit()
        
        # Logout all
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/logout/all",
            headers=auth_headers
        )
        
        assert response.status_code == status.HTTP_204_NO_CONTENT
        
        # Verify all sessions are terminated
        active_sessions = await auth_service.get_active_sessions(test_user.u_id)
        assert len(active_sessions) == 0
    
    async def test_logout_without_auth(self, async_client: AsyncClient):
        """Test logout without authentication."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/logout"
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.integration
class TestRefreshToken:
    """Test refresh token endpoint."""
    
    async def test_refresh_token_success(
        self,
        async_client: AsyncClient,
        test_user: User,
        db_session
    ):
        """Test successful token refresh."""
        # Login first
        auth_service = AuthService(db_session)
        session_data = await auth_service.create_user_session(
            user=test_user,
            ip_address="127.0.0.1",
            user_agent="pytest"
        )
        await db_session.commit()
        
        # Refresh token
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/refresh",
            json={"refresh_token": session_data["refresh_token"]}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        # New access token should be different
        assert data["access_token"] != session_data["access_token"]
    
    async def test_refresh_token_invalid(self, async_client: AsyncClient):
        """Test refresh with invalid token."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/refresh",
            json={"refresh_token": "invalid-token"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    async def test_refresh_token_expired(
        self,
        async_client: AsyncClient,
        test_user: User,
        db_session
    ):
        """Test refresh with expired token."""
        # Create expired session
        session = UserSession(
            us_user_id=test_user.u_id,
            us_refresh_token_hash=security.hash_token("expired-token"),
            us_expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            us_ip_address="127.0.0.1",
            us_user_agent="pytest"
        )
        db_session.add(session)
        await db_session.commit()
        
        # Try to use expired token
        response = await async_client.post(
            f"{settings.API_V1_STR}/auth/refresh",
            json={"refresh_token": "expired-token"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
class TestTwoFactorAuth:
    """Test two-factor authentication."""
    
    async def test_setup_2fa(
        self,
        async_client: AsyncClient,
        auth_headers: dict,
        test_user: User,
        db_session
    ):
        """Test 2FA setup."""
        # Mock 2FA service
        with patch.object(TwoFactorService, 'setup_2fa') as mock_setup:
            mock_setup.return_value = {
                "method": "TOTP",
                "secret": "JBSWY3DPEHPK3PXP",
                "qr_code": "data:image/png;base64,fake-qr",
                "backup_codes": ["ABCD-1234", "EFGH-5678"]
            }
            
            response = await async_client.post(
                f"{settings.API_V1_STR}/auth/2fa/setup",
                headers=auth_headers
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            assert "secret" in data
            assert "qr_code" in data
            assert "backup_codes" in data
            assert len(data["backup_codes"]) > 0
    
    async def test_enable_2fa(
        self,
        async_client: AsyncClient,
        auth_headers: dict,
        test_user: User,
        db_session
    ):
        """Test enabling 2FA."""
        # Setup 2FA first
        two_fa_service = TwoFactorService(db_session)
        setup_data = await two_fa_service.setup_2fa(
            user_id=test_user.u_id,
            method="TOTP"
        )
        
        # Mock TOTP verification
        with patch.object(TwoFactorService, 'enable_2fa') as mock_enable:
            mock_enable.return_value = True
            
            response = await async_client.post(
                f"{settings.API_V1_STR}/auth/2fa/enable",
                headers=auth_headers,
                json={
                    "method": "TOTP",
                    "verification_code": "123456"
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
    
    async def test_login_with_2fa(
        self,
        async_client: AsyncClient,
        test_user: User,
        db_session
    ):
        """Test login flow with 2FA enabled."""
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