"""
User management endpoints untuk API v1.
Menangani registrasi, profile management, dan operasi user lainnya.
"""

from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies.auth import get_current_active_user, get_current_user_optional
from app.api.dependencies.database import get_db
from app.api.dependencies.rate_limit import RateLimitDependency
from app.core.config import settings
from app.core.constants import ResponseMessage, AuditAction, TokenType, LogoutReason 
from app.core.exceptions import (
    ConflictError,
    ValidationError,
    NotFoundError,
    WeakPasswordException,
    TokenError 
)
from app.models.user import User
from app.schemas.user import (
    UserCreate,
    UserResponse,
    UserUpdate,
    UserListResponse,
    PasswordChange,
    EmailVerification,
    PasswordResetRequest,
    PasswordResetConfirm
)
from app.schemas.response import MessageResponse
from app.services.user import UserService
from app.services.email import EmailService
from app.services.token import TokenService
from app.services.audit import AuditService
from app.services.auth import AuthService

router = APIRouter(prefix="/users", tags=["users"])


@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def signup(
    request: Request,
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    rate_limit: RateLimitDependency = Depends(
        RateLimitDependency(
            max_requests=10,
            window_seconds=3600,
            namespace="signup"
        )
    )
) -> UserResponse:
    """
    Register new user account.
    
    Proses signup:
    1. Validasi input data
    2. Check email/username uniqueness
    3. Validate password strength
    4. Create user account
    5. Send verification email
    6. Log audit
    
    Args:
        request: FastAPI request object
        user_data: User registration data
        db: Database session
        rate_limit: Rate limit untuk prevent spam
        
    Returns:
        Created user data
        
    Raises:
        HTTPException: Various validation/conflict errors
    """
    user_service = UserService(db)
    email_service = EmailService()
    token_service = TokenService(db)
    audit_service = AuditService(db)
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # Create user
        user = await user_service.create_user(
            email=user_data.email,
            username=user_data.username,
            password=user_data.password,
            metadata=user_data.metadata,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        # Generate verification token
        if settings.REQUIRE_EMAIL_VERIFICATION:
            token = await token_service.create_token(
                user_id=user.u_id,
                token_type=TokenType.EMAIL_VERIFICATION,
                expires_delta=settings.email_verification_expire_timedelta
            )
            
            # Send verification email
            await email_service.send_verification_email(
                email=user.u_email,
                username=user.u_username,
                verification_token=token
            )
        
        # Log audit
        await audit_service.log_action(
            action=AuditAction.ACCOUNT_CREATED,
            user_id=user.u_id,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"email": user.u_email, "username": user.u_username}
        )
        
        return UserResponse.model_validate(user)
        
    except (ConflictError, ValidationError, WeakPasswordException) as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message
        )
    except Exception as e:
        # Log error
        await audit_service.log_action(
            action=AuditAction.ACCOUNT_CREATED,
            user_id=None,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"error": str(e), "email": user_data.email}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during registration"
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_active_user)
) -> UserResponse:
    """
    Get current authenticated user's profile.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        User profile data
    """
    return UserResponse.model_validate(current_user)


@router.patch("/me", response_model=UserResponse)
async def update_current_user_profile(
    request: Request,
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> UserResponse:
    """
    Update current user's profile.
    
    Args:
        request: FastAPI request object
        user_update: Update data
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Updated user profile
    """
    user_service = UserService(db)
    audit_service = AuditService(db)
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # Track old values for audit
        old_values = {
            "username": current_user.u_username,
            "metadata": current_user.u_metadata
        }
        
        # Update user
        updated_user = await user_service.update_user(
            user_id=current_user.u_id,
            update_data=user_update.model_dump(exclude_unset=True)
        )
        
        # Log audit
        await audit_service.log_action(
            action=AuditAction.PROFILE_UPDATED,
            user_id=current_user.u_id,
            ip_address=client_ip,
            user_agent=user_agent,
            entity_type="USER",
            entity_id=current_user.u_id,
            old_values=old_values,
            new_values=user_update.model_dump(exclude_unset=True)
        )
        
        return UserResponse.model_validate(updated_user)
        
    except (ValidationError, ConflictError) as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating profile"
        )


@router.post("/me/change-password", response_model=MessageResponse)
async def change_password(
    request: Request,
    password_data: PasswordChange,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> MessageResponse:
    """
    Change current user's password.
    
    Args:
        request: FastAPI request object
        password_data: Password change data
        current_user: Current authenticated user
        db: Database session
        
    Returns:
        Success message
    """
    user_service = UserService(db)
    auth_service = AuthService(db)
    audit_service = AuditService(db)
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # Change password
        await user_service.change_password(
            user_id=current_user.u_id,
            current_password=password_data.current_password,
            new_password=password_data.new_password
        )
        
        # Terminate all sessions untuk security
        await auth_service.terminate_all_sessions(
            user_id=current_user.u_id,
            reason=LogoutReason.PASSWORD_CHANGED
        )
        
        # Log audit
        await audit_service.log_action(
            action=AuditAction.PASSWORD_CHANGED,
            user_id=current_user.u_id,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return MessageResponse(
            message=ResponseMessage.PASSWORD_CHANGED,
            details={"sessions_terminated": True}
        )
        
    except (ValidationError, WeakPasswordException) as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while changing password"
        )


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(
    request: Request,
    verification_data: EmailVerification,
    db: AsyncSession = Depends(get_db)
) -> MessageResponse:
    """
    Verify user's email address.
    
    Args:
        request: FastAPI request object
        verification_data: Email verification data
        db: Database session
        
    Returns:
        Success message
    """
    user_service = UserService(db)
    token_service = TokenService(db)
    audit_service = AuditService(db)
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # Verify token and get user
        user = await token_service.verify_and_use_token(
            token=verification_data.token,
            token_type=TokenType.EMAIL_VERIFICATION
        )
        
        # Mark email as verified
        await user_service.verify_email(user.u_id)
        
        # Log audit
        await audit_service.log_action(
            action=AuditAction.ACCOUNT_VERIFIED,
            user_id=user.u_id,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return MessageResponse(
            message=ResponseMessage.EMAIL_VERIFIED
        )
        
    except TokenError as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during email verification"
        )


@router.post("/request-password-reset", response_model=MessageResponse)
async def request_password_reset(
    request: Request,
    reset_request: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
    rate_limit: RateLimitDependency = Depends(
        RateLimitDependency(
            max_requests=3,
            window_seconds=3600,
            namespace="password_reset"
        )
    )
) -> MessageResponse:
    """
    Request password reset token.
    
    Args:
        request: FastAPI request object
        reset_request: Password reset request data
        db: Database session
        rate_limit: Rate limit untuk prevent abuse
        
    Returns:
        Success message (always, untuk security)
    """
    user_service = UserService(db)
    email_service = EmailService()
    token_service = TokenService(db)
    audit_service = AuditService(db)
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # Find user by email
        user = await user_service.get_user_by_email(reset_request.email)
        
        if user:
            # Generate reset token
            token = await token_service.create_token(
                user_id=user.u_id,
                token_type=TokenType.PASSWORD_RESET,
                expires_delta=settings.password_reset_expire_timedelta
            )
            
            # Send reset email
            await email_service.send_password_reset_email(
                email=user.u_email,
                username=user.u_username,
                reset_token=token
            )
            
            # Log audit
            await audit_service.log_action(
                action=AuditAction.PASSWORD_RESET_REQUESTED,
                user_id=user.u_id,
                ip_address=client_ip,
                user_agent=user_agent
            )
    
    except Exception:
        # Don't reveal any error untuk security
        pass
    
    # Always return success untuk prevent email enumeration
    return MessageResponse(
        message=ResponseMessage.PASSWORD_RESET_REQUESTED
    )


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    request: Request,
    reset_data: PasswordResetConfirm,
    db: AsyncSession = Depends(get_db)
) -> MessageResponse:
    """
    Reset password dengan token.
    
    Args:
        request: FastAPI request object
        reset_data: Password reset confirmation data
        db: Database session
        
    Returns:
        Success message
    """
    user_service = UserService(db)
    token_service = TokenService(db)
    auth_service = AuthService(db)
    audit_service = AuditService(db)
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # Verify token and get user
        user = await token_service.verify_and_use_token(
            token=reset_data.token,
            token_type=TokenType.PASSWORD_RESET
        )
        
        # Reset password
        await user_service.reset_password(
            user_id=user.u_id,
            new_password=reset_data.new_password
        )
        
        # Terminate all sessions
        await auth_service.terminate_all_sessions(
            user_id=user.u_id,
            reason=LogoutReason.PASSWORD_CHANGED
        )
        
        # Log audit
        await audit_service.log_action(
            action=AuditAction.PASSWORD_RESET_COMPLETED,
            user_id=user.u_id,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return MessageResponse(
            message=ResponseMessage.PASSWORD_RESET_SUCCESS
        )
        
    except (TokenError, ValidationError, WeakPasswordException) as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during password reset"
        )