"""
Tests for business logic services.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock
from uuid import uuid4

from app.services.user import UserService
from app.services.auth import AuthService
from app.services.token import TokenService
from app.services.device import DeviceService
from app.services.audit import AuditService
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    InvalidCredentialsException,
    WeakPasswordException,
    TokenError
)
from app.core.constants import TokenType, AuditAction


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.requires_db
class TestUserService:
    """Test UserService business logic."""
    
    async def test_create_user_success(self, db_session):
        """Test successful user creation."""
        user_service = UserService(db_session)
        
        user = await user_service.create_user(
            email="newuser@example.com",
            username="newuser",
            password="StrongPassword123!",
            metadata={"source": "test"}
        )
        
        assert user.u_email == "newuser@example.com"
        assert user.u_username == "newuser"
        assert user.verify_password("StrongPassword123!")
        assert user.u_metadata["source"] == "test"
        assert not user.u_is_verified
    
    async def test_create_user_duplicate_email(self, db_session, test_user):
        """Test creating user with duplicate email."""
        user_service = UserService(db_session)
        
        with pytest.raises(ConflictError) as exc_info:
            await user_service.create_user(
                email=test_user.u_email,
                username="different",
                password="Password123!"
            )
        
        assert "Email already registered" in str(exc_info.value)
    
    async def test_create_user_weak_password(self, db_session):
        """Test creating user with weak password."""
        user_service = UserService(db_session)
        
        with pytest.raises(WeakPasswordException) as exc_info:
            await user_service.create_user(
                email="weak@example.com",
                username="weakuser",
                password="weak"
            )
        
        assert "does not meet requirements" in str(exc_info.value)
    
    async def test_update_user(self, db_session, test_user):
        """Test updating user profile."""
        user_service = UserService(db_session)
        
        updated_user = await user_service.update_user(
            user_id=test_user.u_id,
            update_data={
                "username": "updatedname",
                "metadata": {"bio": "Test bio"}
            }
        )
        
        assert updated_user.u_username == "updatedname"
        assert updated_user.u_metadata["bio"] == "Test bio"
    
    async def test_change_password(self, db_session, test_user):
        """Test changing user password."""
        user_service = UserService(db_session)
        
        result = await user_service.change_password(
            user_id=test_user.u_id,
            current_password="TestPassword123!",
            new_password="NewPassword456!"
        )
        
        assert result is True
        
        # Verify new password works
        await db_session.refresh(test_user)
        assert test_user.verify_password("NewPassword456!")
    
    async def test_verify_email(self, db_session, test_user_unverified):
        """Test email verification."""
        user_service = UserService(db_session)
        
        result = await user_service.verify_email(test_user_unverified.u_id)
        
        assert result is True
        await db_session.refresh(test_user_unverified)
        assert test_user_unverified.u_is_verified is True
    
    async def test_lock_unlock_account(self, db_session, test_user):
        """Test account locking and unlocking."""
        user_service = UserService(db_session)
        
        # Lock account
        locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
        await user_service.lock_user_account(
            user_id=test_user.u_id,
            locked_until=locked_until,
            reason="Test lock"
        )
        
        await db_session.refresh(test_user)
        assert test_user.u_is_locked is True
        assert test_user.is_locked_now is True
        
        # Unlock account
        await user_service.unlock_user_account(test_user.u_id)
        
        await db_session.refresh(test_user)
        assert test_user.u_is_locked is False
        assert test_user.is_locked_now is False


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.requires_db
class TestAuthService:
    """Test AuthService business logic."""
    
    async def test_authenticate_user_success(self, db_session, test_user):
        """Test successful authentication."""
        auth_service = AuthService(db_session)
        
        result = await auth_service.authenticate_user(
            email=test_user.u_email,
            password="TestPassword123!",
            ip_address="127.0.0.1"
        )
        
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["user"].u_id == test_user.u_id
        assert result["requires_2fa"] is False
    
    async def test_authenticate_user_invalid_password(self, db_session, test_user):
        """Test authentication with invalid password."""
        auth_service = AuthService(db_session)
        
        with pytest.raises(InvalidCredentialsException):
            await auth_service.authenticate_user(
                email=test_user.u_email,
                password="WrongPassword",
                ip_address="127.0.0.1"
            )
    
    async def test_refresh_access_token(self, db_session, test_user):
        """Test refreshing access token."""
        auth_service = AuthService(db_session)
        
        # Create initial session
        session_data = await auth_service.create_user_session(
            user=test_user,
            ip_address="127.0.0.1"
        )
        await db_session.commit()
        
        # Refresh token
        result = await auth_service.refresh_access_token(
            refresh_token=session_data["refresh_token"],
            ip_address="127.0.0.1"
        )
        
        assert "access_token" in result
        assert result["user_id"] == test_user.u_id
    
    async def test_logout_user(self, db_session, test_user):
        """Test user logout."""
        auth_service = AuthService(db_session)
        
        # Create session
        session_data = await auth_service.create_user_session(
            user=test_user,
            ip_address="127.0.0.1"
        )
        await db_session.commit()
        
        # Logout
        result = await auth_service.logout_user(
            user_id=test_user.u_id,
            refresh_token=session_data["refresh_token"]
        )
        
        assert result is True
        
        # Verify session is terminated
        active_sessions = await auth_service.get_active_sessions(test_user.u_id)
        assert len(active_sessions) == 0
    
    async def test_terminate_all_sessions(self, db_session, test_user):
        """Test terminating all user sessions."""
        auth_service = AuthService(db_session)
        
        # Create multiple sessions
        for i in range(3):
            await auth_service.create_user_session(
                user=test_user,
                ip_address=f"127.0.0.{i}"
            )
        await db_session.commit()
        
        # Terminate all
        terminated_count = await auth_service.terminate_all_sessions(test_user.u_id)
        
        assert terminated_count == 3
        
        # Verify all terminated
        active_sessions = await auth_service.get_active_sessions(test_user.u_id)
        assert len(active_sessions) == 0


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.requires_db
class TestTokenService:
    """Test TokenService business logic."""
    
    async def test_create_email_verification_token(self, db_session, test_user):
        """Test creating email verification token."""
        token_service = TokenService(db_session)
        
        token = await token_service.create_token(
            user_id=test_user.u_id,
            token_type=TokenType.EMAIL_VERIFICATION
        )
        
        assert isinstance(token, str)
        assert len(token) > 20
    
    async def test_verify_token_success(self, db_session, test_user):
        """Test verifying valid token."""
        token_service = TokenService(db_session)
        
        # Create token
        token = await token_service.create_token(
            user_id=test_user.u_id,
            token_type=TokenType.EMAIL_VERIFICATION
        )
        
        # Verify token
        user_token = await token_service.verify_token(
            token=token,
            token_type=TokenType.EMAIL_VERIFICATION,
            mark_as_used=False
        )
        
        assert user_token.ut_user_id == test_user.u_id
        assert not user_token.ut_is_used
    
    async def test_verify_invalid_token(self, db_session):
        """Test verifying invalid token."""
        token_service = TokenService(db_session)
        
        with pytest.raises(TokenError):
            await token_service.verify_token(
                token="invalid-token",
                token_type=TokenType.EMAIL_VERIFICATION
            )
    
    async def test_verify_and_use_token(self, db_session, test_user):
        """Test verifying and marking token as used."""
        token_service = TokenService(db_session)
        
        # Create token
        token = await token_service.create_token(
            user_id=test_user.u_id,
            token_type=TokenType.PASSWORD_RESET
        )
        
        # Verify and use
        user = await token_service.verify_and_use_token(
            token=token,
            token_type=TokenType.PASSWORD_RESET
        )
        
        assert user.u_id == test_user.u_id
        
        # Try to use again
        with pytest.raises(TokenError):
            await token_service.verify_and_use_token(
                token=token,
                token_type=TokenType.PASSWORD_RESET
            )
    
    async def test_create_api_key(self, db_session, test_user):
        """Test creating API key."""
        token_service = TokenService(db_session)
        
        api_key, token_obj = await token_service.create_api_key(
            user_id=test_user.u_id,
            name="Test API Key",
            scopes=["read:users", "write:users"]
        )
        
        assert api_key.startswith("sk_live_")
        assert token_obj.ut_token_type == TokenType.API_KEY
        assert token_obj.ut_metadata["name"] == "Test API Key"
        assert "read:users" in token_obj.ut_metadata["scopes"]


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.requires_db
class TestDeviceService:
    """Test DeviceService business logic."""
    
    async def test_track_device(self, db_session, test_user, sample_device_info):
        """Test tracking user device."""
        device_service = DeviceService(db_session)
        
        device = await device_service.track_device(
            user_id=test_user.u_id,
            device_info=sample_device_info,
            ip_address="127.0.0.1"
        )
        
        assert device.ud_user_id == test_user.u_id
        assert device.ud_device_id == sample_device_info["device_id"]
        assert device.ud_device_name == sample_device_info["device_name"]
        assert device.ud_is_active is True
    
    async def test_trust_device(self, db_session, test_user, sample_device_info):
        """Test trusting a device."""
        device_service = DeviceService(db_session)
        
        # Track device first
        device = await device_service.track_device(
            user_id=test_user.u_id,
            device_info=sample_device_info
        )
        
        # Trust device
        result = await device_service.trust_device(
            user_id=test_user.u_id,
            device_id=device.ud_device_id
        )
        
        assert result is True
        await db_session.refresh(device)
        assert device.ud_is_trusted is True
    
    async def test_is_device_trusted(self, db_session, test_user, sample_device_info):
        """Test checking if device is trusted."""
        device_service = DeviceService(db_session)
        
        # Track and trust device
        device = await device_service.track_device(
            user_id=test_user.u_id,
            device_info=sample_device_info,
            trust_device=True
        )
        
        # Check trust status
        is_trusted = await device_service.is_device_trusted(
            user_id=test_user.u_id,
            device_id=device.ud_device_id
        )
        
        assert is_trusted is True
    
    async def test_remove_device(self, db_session, test_user, sample_device_info):
        """Test removing a device."""
        device_service = DeviceService(db_session)
        
        # Track device
        device = await device_service.track_device(
            user_id=test_user.u_id,
            device_info=sample_device_info
        )
        
        # Remove device
        result = await device_service.remove_device(
            user_id=test_user.u_id,
            device_id=device.ud_device_id
        )
        
        assert result is True
        await db_session.refresh(device)
        assert device.ud_is_active is False


@pytest.mark.asyncio
@pytest.mark.unit
@pytest.mark.requires_db
class TestAuditService:
    """Test AuditService business logic."""
    
    async def test_log_action(self, db_session, test_user):
        """Test logging audit action."""
        audit_service = AuditService(db_session)
        
        audit_log = await audit_service.log_action(
            action=AuditAction.LOGIN_SUCCESS,
            user_id=test_user.u_id,
            ip_address="127.0.0.1",
            user_agent="pytest",
            metadata={"test": True}
        )
        
        assert audit_log.al_action == AuditAction.LOGIN_SUCCESS
        assert audit_log.al_user_id == test_user.u_id
        assert audit_log.al_ip_address == "127.0.0.1"
        assert audit_log.al_metadata["test"] is True
    
    async def test_get_audit_logs(self, db_session, test_user):
        """Test retrieving audit logs."""
        audit_service = AuditService(db_session)
        
        # Create some audit logs
        for i in range(5):
            await audit_service.log_action(
                action=AuditAction.LOGIN_SUCCESS,
                user_id=test_user.u_id,
                ip_address=f"127.0.0.{i}"
            )
        
        # Get logs
        logs, total = await audit_service.get_audit_logs(
            user_id=test_user.u_id,
            page=1,
            per_page=10
        )
        
        assert len(logs) == 5
        assert total == 5
    
    async def test_get_user_activity_summary(self, db_session, test_user):
        """Test getting user activity summary."""
        audit_service = AuditService(db_session)
        
        # Create various audit logs
        actions = [
            AuditAction.LOGIN_SUCCESS,
            AuditAction.LOGIN_SUCCESS,
            AuditAction.LOGIN_FAILED,
            AuditAction.PASSWORD_CHANGED,
            AuditAction.PROFILE_UPDATED
        ]
        
        for action in actions:
            await audit_service.log_action(
                action=action,
                user_id=test_user.u_id
            )
        
        # Get summary
        summary = await audit_service.get_user_activity_summary(
            user_id=test_user.u_id,
            days=30
        )
        
        assert summary["total_actions"] == 5
        assert summary["action_counts"][AuditAction.LOGIN_SUCCESS] == 2
        assert summary["action_counts"][AuditAction.LOGIN_FAILED] == 1