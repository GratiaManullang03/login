"""
Tests for user management endpoints.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi import status
from httpx import AsyncClient

from app.core.config import settings
from app.models.user import User
from app.services.token import TokenService
from app.core.constants import TokenType


@pytest.mark.asyncio
@pytest.mark.integration
class TestUserSignup:
    """Test user signup endpoint."""
    
    async def test_signup_success(
        self,
        async_client: AsyncClient,
        mock_email_service,
        generate_test_user_data
    ):
        """Test successful user signup."""
        user_data = generate_test_user_data(1)
        
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/signup",
            json=user_data
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        
        assert data["u_email"] == user_data["email"]
        assert data["u_username"] == user_data["username"]
        assert "u_id" in data
        assert data["u_is_verified"] is False
        
        # Check that verification email was sent
        assert len(mock_email_service) == 1
    
    async def test_signup_duplicate_email(
        self,
        async_client: AsyncClient,
        test_user: User,
        generate_test_user_data
    ):
        """Test signup with duplicate email."""
        user_data = generate_test_user_data(2)
        user_data["email"] = test_user.u_email  # Use existing email
        
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/signup",
            json=user_data
        )
        
        assert response.status_code == status.HTTP_409_CONFLICT
        assert "already registered" in response.json()["detail"]
    
    async def test_signup_weak_password(
        self,
        async_client: AsyncClient,
        generate_test_user_data
    ):
        """Test signup with weak password."""
        user_data = generate_test_user_data(3)
        user_data["password"] = "weak"
        user_data["confirm_password"] = "weak"
        
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/signup",
            json=user_data
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    
    async def test_signup_password_mismatch(
        self,
        async_client: AsyncClient,
        generate_test_user_data
    ):
        """Test signup with password mismatch."""
        user_data = generate_test_user_data(4)
        user_data["confirm_password"] = "DifferentPassword123!"
        
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/signup",
            json=user_data
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert "do not match" in str(response.json()["detail"])
    
    async def test_signup_invalid_email(self, async_client: AsyncClient):
        """Test signup with invalid email format."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/signup",
            json={
                "email": "invalid-email",
                "username": "testuser",
                "password": "Password123!",
                "confirm_password": "Password123!"
            }
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.asyncio
@pytest.mark.integration
class TestGetCurrentUser:
    """Test get current user endpoint."""
    
    async def test_get_me_success(
        self,
        async_client: AsyncClient,
        test_user: User,
        auth_headers: dict
    ):
        """Test getting current user profile."""
        response = await async_client.get(
            f"{settings.API_V1_STR}/users/me",
            headers=auth_headers
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert data["u_id"] == str(test_user.u_id)
        assert data["u_email"] == test_user.u_email
        assert data["u_username"] == test_user.u_username
    
    async def test_get_me_unauthorized(self, async_client: AsyncClient):
        """Test getting current user without auth."""
        response = await async_client.get(
            f"{settings.API_V1_STR}/users/me"
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    async def test_get_me_invalid_token(self, async_client: AsyncClient):
        """Test getting current user with invalid token."""
        response = await async_client.get(
            f"{settings.API_V1_STR}/users/me",
            headers={"Authorization": "Bearer invalid-token"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
@pytest.mark.integration
class TestUpdateUser:
    """Test update user endpoint."""
    
    async def test_update_profile_success(
        self,
        async_client: AsyncClient,
        test_user: User,
        auth_headers: dict
    ):
        """Test updating user profile."""
        update_data = {
            "username": "newusername",
            "metadata": {"bio": "New bio"}
        }
        
        response = await async_client.patch(
            f"{settings.API_V1_STR}/users/me",
            headers=auth_headers,
            json=update_data
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        assert data["u_username"] == "newusername"
        assert data["u_metadata"]["bio"] == "New bio"
    
    async def test_update_username_duplicate(
        self,
        async_client: AsyncClient,
        test_user: User,
        test_admin_user: User,
        auth_headers: dict
    ):
        """Test updating username to existing one."""
        response = await async_client.patch(
            f"{settings.API_V1_STR}/users/me",
            headers=auth_headers,
            json={"username": test_admin_user.u_username}
        )
        
        assert response.status_code == status.HTTP_409_CONFLICT
        assert "already taken" in response.json()["detail"]


@pytest.mark.asyncio
@pytest.mark.integration
class TestPasswordManagement:
    """Test password-related endpoints."""
    
    async def test_change_password_success(
        self,
        async_client: AsyncClient,
        test_user: User,
        auth_headers: dict,
        db_session
    ):
        """Test changing password."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/me/change-password",
            headers=auth_headers,
            json={
                "current_password": "TestPassword123!",
                "new_password": "NewPassword456!",
                "confirm_new_password": "NewPassword456!"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert "changed" in response.json()["message"]
        
        # Verify old password no longer works
        await db_session.refresh(test_user)
        assert not test_user.verify_password("TestPassword123!")
        assert test_user.verify_password("NewPassword456!")
    
    async def test_change_password_wrong_current(
        self,
        async_client: AsyncClient,
        auth_headers: dict
    ):
        """Test changing password with wrong current password."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/me/change-password",
            headers=auth_headers,
            json={
                "current_password": "WrongPassword123!",
                "new_password": "NewPassword456!",
                "confirm_new_password": "NewPassword456!"
            }
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    async def test_request_password_reset(
        self,
        async_client: AsyncClient,
        test_user: User,
        mock_email_service
    ):
        """Test requesting password reset."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/request-password-reset",
            json={"email": test_user.u_email}
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert "reset instructions sent" in response.json()["message"]
        
        # Check email was sent
        assert len(mock_email_service) == 1
    
    async def test_reset_password_success(
        self,
        async_client: AsyncClient,
        test_user: User,
        db_session
    ):
        """Test resetting password with valid token."""
        # Create reset token
        token_service = TokenService(db_session)
        reset_token = await token_service.create_token(
            user_id=test_user.u_id,
            token_type=TokenType.PASSWORD_RESET
        )
        
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/reset-password",
            json={
                "token": reset_token,
                "new_password": "ResetPassword789!",
                "confirm_password": "ResetPassword789!"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify new password works
        await db_session.refresh(test_user)
        assert test_user.verify_password("ResetPassword789!")


@pytest.mark.asyncio
@pytest.mark.integration
class TestEmailVerification:
    """Test email verification endpoint."""
    
    async def test_verify_email_success(
        self,
        async_client: AsyncClient,
        test_user_unverified: User,
        db_session
    ):
        """Test successful email verification."""
        # Create verification token
        token_service = TokenService(db_session)
        verify_token = await token_service.create_token(
            user_id=test_user_unverified.u_id,
            token_type=TokenType.EMAIL_VERIFICATION
        )
        
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/verify-email",
            json={"token": verify_token}
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert "verified" in response.json()["message"]
        
        # Check user is verified
        await db_session.refresh(test_user_unverified)
        assert test_user_unverified.u_is_verified is True
    
    async def test_verify_email_invalid_token(self, async_client: AsyncClient):
        """Test email verification with invalid token."""
        response = await async_client.post(
            f"{settings.API_V1_STR}/users/verify-email",
            json={"token": "invalid-token"}
        )
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert "Invalid token" in response.json()["detail"]
    
    async def test_verify_email_expired_token(
        self,
        async_client: AsyncClient,
        test_user_unverified: User,
        db_session
    ):
        """Test email verification with expired token."""
        # Create expired token
        from datetime import timedelta
        token_service = TokenService(db_session)
        
        # Mock expired token
        with patch.object(TokenService, 'verify_token') as mock_verify:
            from app.core.exceptions import ExpiredTokenException
            mock_verify.side_effect = ExpiredTokenException("Token has expired")
            
            response = await async_client.post(
                f"{settings.API_V1_STR}/users/verify-email",
                json={"token": "expired-token"}
            )
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            assert "expired" in response.json()["detail"]