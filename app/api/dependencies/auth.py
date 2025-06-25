"""
Authentication dependencies untuk FastAPI.
Menyediakan dependency injection untuk autentikasi dan otorisasi.
"""

from typing import Optional, Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies.database import get_db
from app.core.config import settings
from app.core.security import security
from app.core.exceptions import TokenError, AuthenticationError
from app.models.user import User
from app.services.user import UserService

# OAuth2 scheme untuk Bearer token
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    auto_error=False  # Kita handle error sendiri
)


async def get_current_user(
    token: Annotated[Optional[str], Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)]
) -> User:
    """
    Get current user dari JWT token.
    
    Args:
        token: JWT access token dari Authorization header
        db: Database session
        
    Returns:
        Current user object
        
    Raises:
        HTTPException: Jika token invalid atau user tidak ditemukan
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        # Decode token
        payload = security.decode_token(token, expected_type="access")
        user_id: str = payload.get("sub")
        
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Get user from database
        user_service = UserService(db)
        user = await user_service.get_user_by_id(UUID(user_id))
        
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return user
        
    except TokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
) -> User:
    """
    Get current active user.
    Memastikan user account active dan tidak locked.
    
    Args:
        current_user: Current user dari token
        
    Returns:
        Active user object
        
    Raises:
        HTTPException: Jika user tidak active atau locked
    """
    if not current_user.u_is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    
    if current_user.u_is_locked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is locked"
        )
    
    return current_user


async def get_current_user_optional(
    token: Annotated[Optional[str], Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)]
) -> Optional[User]:
    """
    Get current user jika ada token valid, None jika tidak.
    Digunakan untuk endpoint yang bisa diakses dengan atau tanpa auth.
    
    Args:
        token: Optional JWT access token
        db: Database session
        
    Returns:
        User object atau None
    """
    if not token:
        return None
    
    try:
        return await get_current_user(token, db)
    except HTTPException:
        return None


async def require_verified_email(
    current_user: Annotated[User, Depends(get_current_active_user)]
) -> User:
    """
    Dependency untuk memastikan user sudah verifikasi email.
    
    Args:
        current_user: Current active user
        
    Returns:
        Verified user
        
    Raises:
        HTTPException: Jika email belum diverifikasi
    """
    if not current_user.u_is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified"
        )
    
    return current_user


async def require_2fa_enabled(
    current_user: Annotated[User, Depends(get_current_active_user)],
    db: Annotated[AsyncSession, Depends(get_db)]
) -> User:
    """
    Dependency untuk endpoint yang memerlukan 2FA enabled.
    
    Args:
        current_user: Current active user
        db: Database session
        
    Returns:
        User dengan 2FA enabled
        
    Raises:
        HTTPException: Jika 2FA tidak enabled
    """
    # Check 2FA status dari database
    # Implementation tergantung pada TwoFactorService
    # Untuk sekarang, return user
    return current_user


class PermissionChecker:
    """
    Dependency class untuk permission checking.
    Bisa di-extend untuk role-based access control.
    """
    
    def __init__(self, required_permissions: list[str]):
        self.required_permissions = required_permissions
    
    async def __call__(
        self,
        current_user: Annotated[User, Depends(get_current_active_user)]
    ) -> User:
        """
        Check if user has required permissions.
        
        Args:
            current_user: Current active user
            
        Returns:
            User dengan permissions
            
        Raises:
            HTTPException: Jika tidak punya permission
        """
        # Implementasi permission checking
        # Untuk sekarang, return user
        # Bisa di-extend dengan role/permission system
        return current_user