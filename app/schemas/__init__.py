"""
Schemas module untuk SecureAuth API.
Berisi semua Pydantic schemas untuk request/response validation.
"""

from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    TokenResponse,
    RefreshTokenRequest,
    LogoutRequest,
    TwoFactorVerifyRequest,
    TwoFactorSetupResponse,
    TwoFactorEnableRequest,
    DeviceInfo
)
from app.schemas.user import (
    UserCreate,
    UserUpdate,
    UserResponse,
    UserListResponse,
    PasswordChange,
    EmailVerification,
    PasswordResetRequest,
    PasswordResetConfirm,
    UserProfile,
    UserSecurity
)
from app.schemas.token import (
    TokenCreate,
    TokenResponse as TokenInfoResponse,
    TokenVerify,
    TokenListResponse
)
from app.schemas.response import (
    MessageResponse,
    ErrorResponse,
    PaginationParams,
    PaginatedResponse,
    HealthCheckResponse,
    ValidationErrorDetail
)

__all__ = [
    # Auth schemas
    "LoginRequest",
    "LoginResponse",
    "TokenResponse",
    "RefreshTokenRequest",
    "LogoutRequest",
    "TwoFactorVerifyRequest",
    "TwoFactorSetupResponse",
    "TwoFactorEnableRequest",
    "DeviceInfo",
    
    # User schemas
    "UserCreate",
    "UserUpdate",
    "UserResponse",
    "UserListResponse",
    "PasswordChange",
    "EmailVerification",
    "PasswordResetRequest",
    "PasswordResetConfirm",
    "UserProfile",
    "UserSecurity",
    
    # Token schemas
    "TokenCreate",
    "TokenInfoResponse",
    "TokenVerify",
    "TokenListResponse",
    
    # Response schemas
    "MessageResponse",
    "ErrorResponse",
    "PaginationParams",
    "PaginatedResponse",
    "HealthCheckResponse",
    "ValidationErrorDetail"
]