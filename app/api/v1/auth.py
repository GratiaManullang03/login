"""
Authentication endpoints untuk API v1.
Menangani login, logout, refresh token, dan operasi autentikasi lainnya.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies.auth import get_current_user, get_current_active_user
from app.api.dependencies.database import get_db
from app.api.dependencies.rate_limit import RateLimitDependency
from app.core.config import settings
from app.core.constants import ResponseMessage, AuditAction, LogoutReason
from app.core.exceptions import (
    InvalidCredentialsException,
    AccountLockedException,
    EmailNotVerifiedException,
    TwoFactorRequiredException,
    TokenError
)
from app.models.user import User
from app.schemas.auth import (
    TokenResponse,
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    LogoutRequest,
    TwoFactorVerifyRequest,
    DeviceInfo
)
from app.services.auth import AuthService
from app.services.audit import AuditService
from app.services.device import DeviceService
from app.services.two_factor import TwoFactorService
from app.middleware.csrf import get_csrf_token

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    device_info: Optional[DeviceInfo] = None,
    db: AsyncSession = Depends(get_db),
    rate_limit: RateLimitDependency = Depends(
        RateLimitDependency(
            max_requests=settings.LOGIN_RATE_LIMIT_PER_MINUTE,
            window_seconds=60,
            namespace="login"
        )
    )
) -> LoginResponse:
    """
    Login endpoint dengan OAuth2 compatible form.
    
    Proses login:
    1. Validasi rate limit
    2. Verifikasi kredensial
    3. Check status akun (locked, verified)
    4. Check 2FA requirement
    5. Generate tokens
    6. Track device
    7. Create session
    8. Log audit
    
    Args:
        request: FastAPI request object untuk mendapatkan IP
        response: FastAPI response object untuk set cookies
        form_data: OAuth2 form dengan username (email) dan password
        device_info: Informasi device dari client (optional)
        db: Database session
        rate_limit: Rate limit dependency
        
    Returns:
        LoginResponse dengan access token dan refresh token
        
    Raises:
        HTTPException: Berbagai error autentikasi
    """
    auth_service = AuthService(db)
    audit_service = AuditService(db)
    
    # Extract client info
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # Attempt login
        result = await auth_service.authenticate_user(
            email=form_data.username,  # OAuth2 form uses 'username' field
            password=form_data.password,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        # Check if 2FA is required
        if result.get("requires_2fa"):
            # Return temporary session ID untuk 2FA verification
            raise TwoFactorRequiredException(
                message=ResponseMessage.TWO_FACTOR_REQUIRED,
                session_id=result.get("session_id")
            )
        
        # Track device jika ada info
        if device_info and result["user"]:
            device_service = DeviceService(db)
            await device_service.track_device(
                user_id=result["user"].u_id,
                device_info=device_info.model_dump(),
                ip_address=client_ip,
                user_agent=user_agent
            )
        
        # Set secure cookie untuk refresh token (optional)
        if settings.USE_SECURE_COOKIES:
            response.set_cookie(
                key="refresh_token",
                value=result["refresh_token"],
                max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                secure=True,
                httponly=True,
                samesite="lax"
            )
        
        return LoginResponse(
            access_token=result["access_token"],
            refresh_token=result["refresh_token"],
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user_id=str(result["user"].u_id),
            requires_2fa=False
        )
        
    except (InvalidCredentialsException, AccountLockedException, 
            EmailNotVerifiedException, TwoFactorRequiredException) as e:
        # Log failed attempt
        await audit_service.log_action(
            action=AuditAction.LOGIN_FAILED,
            user_id=None,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"reason": str(e), "email": form_data.username}
        )
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as e:
        # Log unexpected error
        await audit_service.log_action(
            action=AuditAction.LOGIN_FAILED,
            user_id=None,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"error": str(e), "email": form_data.username}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during login"
        )


@router.post("/login/2fa", response_model=LoginResponse)
async def verify_two_factor(
    request: Request,
    response: Response,
    two_fa_data: TwoFactorVerifyRequest,
    db: AsyncSession = Depends(get_db)
) -> LoginResponse:
    """
    Verify two-factor authentication code.
    
    Args:
        request: FastAPI request object
        response: FastAPI response object
        two_fa_data: 2FA verification data
        db: Database session
        
    Returns:
        LoginResponse dengan tokens setelah 2FA berhasil
        
    Raises:
        HTTPException: Jika 2FA gagal
    """
    auth_service = AuthService(db)
    two_factor_service = TwoFactorService(db)
    audit_service = AuditService(db)
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # Verify 2FA code
        is_valid = await two_factor_service.verify_2fa_code(
            session_id=two_fa_data.session_id,
            code=two_fa_data.code,
            method=two_fa_data.method
        )
        
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ResponseMessage.TWO_FACTOR_INVALID
            )
        
        # Get user from session
        user = await auth_service.get_user_from_2fa_session(two_fa_data.session_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid session"
            )
        
        # Generate tokens
        result = await auth_service.create_user_session(
            user=user,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        # Log successful 2FA
        await audit_service.log_action(
            action=AuditAction.TWO_FACTOR_VERIFIED,
            user_id=user.u_id,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return LoginResponse(
            access_token=result["access_token"],
            refresh_token=result["refresh_token"],
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user_id=str(user.u_id),
            requires_2fa=False
        )
        
    except HTTPException:
        raise
    except Exception as e:
        await audit_service.log_action(
            action=AuditAction.TWO_FACTOR_FAILED,
            user_id=None,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"error": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during 2FA verification"
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    refresh_request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """
    Refresh access token menggunakan refresh token.
    
    Proses:
    1. Validasi refresh token
    2. Check session validity
    3. Generate new access token
    4. Optionally rotate refresh token
    
    Args:
        request: FastAPI request object
        refresh_request: Request dengan refresh token
        db: Database session
        
    Returns:
        TokenResponse dengan access token baru
        
    Raises:
        HTTPException: Jika refresh token invalid
    """
    auth_service = AuthService(db)
    audit_service = AuditService(db)
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # Refresh tokens
        result = await auth_service.refresh_access_token(
            refresh_token=refresh_request.refresh_token,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        # Log token refresh
        await audit_service.log_action(
            action=AuditAction.TOKEN_REFRESH,
            user_id=result["user_id"],
            ip_address=client_ip,
            user_agent=user_agent
        )
        
        return TokenResponse(
            access_token=result["access_token"],
            refresh_token=result.get("refresh_token"),  # Mungkin None jika tidak dirotasi
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        
    except TokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during token refresh"
        )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    logout_request: Optional[LogoutRequest] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> None:
    """
    Logout user dan invalidate session.
    
    Args:
        request: FastAPI request object
        response: FastAPI response object
        logout_request: Optional logout request dengan refresh token
        current_user: Current authenticated user
        db: Database session
    """
    auth_service = AuthService(db)
    audit_service = AuditService(db)
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # Logout user
        if logout_request and logout_request.refresh_token:
            # Logout specific session
            await auth_service.logout_user(
                user_id=current_user.u_id,
                refresh_token=logout_request.refresh_token,
                reason=LogoutReason.USER_INITIATED
            )
        else:
            # Logout dari current session (berdasarkan access token)
            # Implementasi tergantung pada tracking mechanism
            pass
        
        # Clear cookies jika ada
        if settings.USE_SECURE_COOKIES:
            response.delete_cookie("refresh_token")
        
        # Log logout
        await audit_service.log_action(
            action=AuditAction.LOGOUT,
            user_id=current_user.u_id,
            ip_address=client_ip,
            user_agent=user_agent
        )
        
    except Exception as e:
        # Still try to log even if logout fails
        await audit_service.log_action(
            action=AuditAction.LOGOUT,
            user_id=current_user.u_id,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"error": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during logout"
        )


@router.post("/logout/all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all_sessions(
    request: Request,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> None:
    """
    Logout user dari semua sessions/devices.
    
    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        db: Database session
    """
    auth_service = AuthService(db)
    audit_service = AuditService(db)
    
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    try:
        # Terminate all sessions
        terminated_count = await auth_service.terminate_all_sessions(
            user_id=current_user.u_id,
            reason=LogoutReason.USER_INITIATED
        )
        
        # Log action
        await audit_service.log_action(
            action=AuditAction.ALL_SESSIONS_TERMINATED,
            user_id=current_user.u_id,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"terminated_sessions": terminated_count}
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while terminating sessions"
        )
    

@router.get("/csrf-token")
async def get_csrf_token_endpoint(request: Request) -> Dict[str, str]:
    """
    Get CSRF token for form submissions.
    
    The token is also set as a cookie automatically by the middleware.
    Include this token in your requests as:
    - Header: X-CSRF-Token
    - Form field: csrf_token
    - JSON field: csrf_token
    """
    csrf_token = get_csrf_token(request)
    if not csrf_token:
        # Token will be generated on next GET request
        return {"csrf_token": "", "message": "Token will be generated on page load"}
    
    return {"csrf_token": csrf_token}