"""
User schemas untuk SecureAuth API.
Menangani validasi untuk user creation, updates, dan responses.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List, Annotated 
from uuid import UUID
import re

from pydantic import BaseModel, Field, EmailStr, field_validator, constr, model_validator

from app.core.config import settings


class UserBase(BaseModel):
    """
    Base user schema dengan fields umum.
    """
    email: EmailStr = Field(
        ...,
        description="User email address"
    )
    # username: constr(
    #     min_length=3,
    #     max_length=50,
    #     regex=r'^[a-zA-Z0-9_-]+$'
    # ) = Field(
    #     ...,
    #     description="Username (alphanumeric, underscore, hyphen only)"
    # )
    username: Annotated[str, Field(
        min_length=3,
        max_length=50,
        pattern=r'^[a-zA-Z0-9_-]+$'
    )] = Field(
        ...,
        description="Username (alphanumeric, underscore, hyphen only)"
    )
    
    @field_validator('email')
    def normalize_email(cls, v: str) -> str:
        """Normalize email to lowercase."""
        return v.lower().strip()
    
    @field_validator('username')
    def validate_username(cls, v: str) -> str:
        """Validate username format and reserved words."""
        v = v.strip()
        
        # Check reserved usernames
        reserved = ['admin', 'root', 'system', 'api', 'auth', 'oauth']
        if v.lower() in reserved:
            raise ValueError(f"Username '{v}' is reserved")
        
        return v


class UserCreate(UserBase):
    """
    User creation schema dengan password validation.
    """
    password: Annotated[str, Field(min_length=8)] = Field(
        ...,
        description="User password (min 8 characters)"
    )
    confirm_password: str = Field(
        ...,
        description="Password confirmation"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional user metadata"
    )
    
    @field_validator('password')
    def validate_password_strength(cls, v: str) -> str:
        """
        Validate password meets security requirements.
        """
        # Check minimum length (already handled by constr)
        if len(v) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
        
        # Check complexity requirements
        errors = []
        
        if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', v):
            errors.append("Password must contain at least one uppercase letter")
        
        if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', v):
            errors.append("Password must contain at least one lowercase letter")
        
        if settings.PASSWORD_REQUIRE_NUMBERS and not re.search(r'\d', v):
            errors.append("Password must contain at least one number")
        
        if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            errors.append("Password must contain at least one special character")
        
        # Check for common passwords
        common_passwords = ['password', '12345678', 'qwerty', 'admin123']
        if v.lower() in common_passwords:
            errors.append("Password is too common")
        
        if errors:
            raise ValueError("; ".join(errors))
        
        return v
    
    @model_validator(mode='before')
    def validate_passwords_match(cls, values: dict) -> dict:
        """Validate password and confirm_password match."""
        password = values.get('password')
        confirm_password = values.get('confirm_password')
        
        if password and confirm_password and password != confirm_password:
            raise ValueError("Passwords do not match")
        
        return values
    
    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com",
                "username": "johndoe",
                "password": "SecurePassword123!",
                "confirm_password": "SecurePassword123!",
                "metadata": {
                    "first_name": "John",
                    "last_name": "Doe"
                }
            }
        }


class UserUpdate(BaseModel):
    """
    User update schema - all fields optional.
    """
    # username: Optional[constr(
    #     min_length=3,
    #     max_length=50,
    #     regex=r'^[a-zA-Z0-9_-]+$'
    # )] = Field(None, description="New username")
    # metadata: Optional[Dict[str, Any]] = Field(
    #     None,
    #     description="Updated metadata"
    # )
    username: Optional[Annotated[str, Field(
        min_length=3,
        max_length=50,
        pattern=r'^[a-zA-Z0-9_-]+$'
    )]] = Field(None, description="New username")
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Updated metadata"
    )
    
    @field_validator('username')
    def validate_username(cls, v: Optional[str]) -> Optional[str]:
        """Validate username if provided."""
        if v is None:
            return v
        
        v = v.strip()
        reserved = ['admin', 'root', 'system', 'api', 'auth', 'oauth']
        if v.lower() in reserved:
            raise ValueError(f"Username '{v}' is reserved")
        
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "username": "newusername",
                "metadata": {
                    "bio": "Updated bio"
                }
            }
        }


class UserResponse(BaseModel):
    """
    User response schema untuk API responses.
    """
    u_id: UUID = Field(..., description="User ID")
    u_email: EmailStr = Field(..., description="User email")
    u_username: str = Field(..., description="Username")
    u_is_active: bool = Field(..., description="Whether user is active")
    u_is_verified: bool = Field(..., description="Whether email is verified")
    u_is_locked: bool = Field(..., description="Whether account is locked")
    u_email_verified_at: Optional[datetime] = Field(None, description="Email verification timestamp")
    u_created_at: datetime = Field(..., description="Account creation timestamp")
    u_updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    u_last_login_at: Optional[datetime] = Field(None, description="Last login timestamp")
    u_metadata: Optional[Dict[str, Any]] = Field(None, description="User metadata")
    has_2fa_enabled: bool = Field(False, description="Whether 2FA is enabled")
    
    class Config:
        orm_mode = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            UUID: lambda v: str(v)
        }
        schema_extra = {
            "example": {
                "u_id": "550e8400-e29b-41d4-a716-446655440000",
                "u_email": "user@example.com",
                "u_username": "johndoe",
                "u_is_active": True,
                "u_is_verified": True,
                "u_is_locked": False,
                "u_email_verified_at": "2024-01-15T10:00:00Z",
                "u_created_at": "2024-01-01T00:00:00Z",
                "u_updated_at": "2024-01-15T10:00:00Z",
                "u_last_login_at": "2024-01-15T09:00:00Z",
                "u_metadata": {
                    "first_name": "John",
                    "last_name": "Doe"
                },
                "has_2fa_enabled": False
            }
        }


class UserListResponse(BaseModel):
    """
    Paginated user list response.
    """
    users: List[UserResponse] = Field(..., description="List of users")
    total: int = Field(..., description="Total number of users")
    page: int = Field(..., description="Current page")
    per_page: int = Field(..., description="Items per page")
    pages: int = Field(..., description="Total pages")
    
    class Config:
        schema_extra = {
            "example": {
                "users": [],
                "total": 100,
                "page": 1,
                "per_page": 20,
                "pages": 5
            }
        }


class PasswordChange(BaseModel):
    """
    Password change request schema.
    """
    current_password: str = Field(
        ...,
        description="Current password"
    )
    new_password: Annotated[str, Field(min_length=8)] = Field(
        ...,
        description="New password"
    )
    confirm_new_password: str = Field(
        ...,
        description="Confirm new password"
    )
    
    @field_validator('new_password')
    def validate_password_strength(cls, v: str, values: dict) -> str:
        """Validate new password strength and not same as current."""
        # Check if same as current password
        current = values.get('current_password')
        if current and v == current:
            raise ValueError("New password must be different from current password")
        
        # Apply same validation as UserCreate
        if len(v) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
        
        errors = []
        
        if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', v):
            errors.append("Password must contain at least one uppercase letter")
        
        if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', v):
            errors.append("Password must contain at least one lowercase letter")
        
        if settings.PASSWORD_REQUIRE_NUMBERS and not re.search(r'\d', v):
            errors.append("Password must contain at least one number")
        
        if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            errors.append("Password must contain at least one special character")
        
        if errors:
            raise ValueError("; ".join(errors))
        
        return v
    
    @model_validator(mode='before')
    def validate_passwords_match(cls, values: dict) -> dict:
        """Validate new passwords match."""
        new_password = values.get('new_password')
        confirm_password = values.get('confirm_new_password')
        
        if new_password and confirm_password and new_password != confirm_password:
            raise ValueError("New passwords do not match")
        
        return values
    
    class Config:
        schema_extra = {
            "example": {
                "current_password": "OldPassword123!",
                "new_password": "NewSecurePassword123!",
                "confirm_new_password": "NewSecurePassword123!"
            }
        }


class EmailVerification(BaseModel):
    """
    Email verification request schema.
    """
    token: str = Field(
        ...,
        description="Email verification token"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class PasswordResetRequest(BaseModel):
    """
    Password reset request schema.
    """
    email: EmailStr = Field(
        ...,
        description="Email address for password reset"
    )
    
    @field_validator('email')
    def normalize_email(cls, v: str) -> str:
        """Normalize email to lowercase."""
        return v.lower().strip()
    
    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com"
            }
        }


class PasswordResetConfirm(BaseModel):
    """
    Password reset confirmation schema.
    """
    token: str = Field(
        ...,
        description="Password reset token"
    )
    new_password: Annotated[str, Field(min_length=8)] = Field(
        ...,
        description="New password"
    )
    confirm_password: str = Field(
        ...,
        description="Confirm new password"
    )
    
    @field_validator('new_password')
    def validate_password_strength(cls, v: str) -> str:
        """Validate password strength."""
        if len(v) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
        
        errors = []
        
        if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', v):
            errors.append("Password must contain at least one uppercase letter")
        
        if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', v):
            errors.append("Password must contain at least one lowercase letter")
        
        if settings.PASSWORD_REQUIRE_NUMBERS and not re.search(r'\d', v):
            errors.append("Password must contain at least one number")
        
        if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            errors.append("Password must contain at least one special character")
        
        if errors:
            raise ValueError("; ".join(errors))
        
        return v
    
    @model_validator(mode='before')
    def validate_passwords_match(cls, values: dict) -> dict:
        """Validate passwords match."""
        new_password = values.get('new_password')
        confirm_password = values.get('confirm_password')
        
        if new_password and confirm_password and new_password != confirm_password:
            raise ValueError("Passwords do not match")
        
        return values
    
    class Config:
        schema_extra = {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "new_password": "NewSecurePassword123!",
                "confirm_password": "NewSecurePassword123!"
            }
        }


class UserProfile(BaseModel):
    """
    Extended user profile schema dengan informasi tambahan.
    """
    u_id: UUID
    u_email: EmailStr
    u_username: str
    u_is_active: bool
    u_is_verified: bool
    u_created_at: datetime
    u_last_login_at: Optional[datetime]
    u_metadata: Optional[Dict[str, Any]]
    
    # Security info
    has_2fa_enabled: bool
    active_sessions_count: int
    trusted_devices_count: int
    
    # Activity summary
    total_logins: int
    failed_login_attempts: int
    password_last_changed: Optional[datetime]
    
    class Config:
        orm_mode = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            UUID: lambda v: str(v)
        }


class UserSecurity(BaseModel):
    """
    User security settings schema.
    """
    has_2fa_enabled: bool = Field(..., description="Whether 2FA is enabled")
    two_factor_method: Optional[str] = Field(None, description="2FA method if enabled")
    active_sessions: int = Field(..., description="Number of active sessions")
    trusted_devices: int = Field(..., description="Number of trusted devices")
    last_password_change: Optional[datetime] = Field(None, description="Last password change timestamp")
    account_locked: bool = Field(..., description="Whether account is locked")
    locked_until: Optional[datetime] = Field(None, description="Lock expiration if locked")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
        schema_extra = {
            "example": {
                "has_2fa_enabled": True,
                "two_factor_method": "TOTP",
                "active_sessions": 2,
                "trusted_devices": 1,
                "last_password_change": "2024-01-01T00:00:00Z",
                "account_locked": False,
                "locked_until": None
            }
        }