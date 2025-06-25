"""
Authentication schemas untuk SecureAuth API.
Menangani validasi untuk login, logout, refresh token, dan 2FA.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List, Annotated 
from uuid import UUID

from pydantic import BaseModel, Field, EmailStr, validator, constr

from app.core.constants import DeviceType, Platform, TwoFactorMethod


class DeviceInfo(BaseModel):
    """
    Device information schema untuk tracking devices.
    """
    device_id: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Unique device identifier/fingerprint"
    )
    device_name: Optional[str] = Field(
        None,
        max_length=255,
        description="Human-readable device name"
    )
    device_type: Optional[DeviceType] = Field(
        None,
        description="Type of device (MOBILE, DESKTOP, TABLET)"
    )
    platform: Optional[Platform] = Field(
        None,
        description="Platform (IOS, ANDROID, WINDOWS, etc)"
    )
    browser: Optional[str] = Field(
        None,
        max_length=100,
        description="Browser name"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional device metadata"
    )
    
    class Config:
        use_enum_values = True
        schema_extra = {
            "example": {
                "device_id": "550e8400-e29b-41d4-a716-446655440000",
                "device_name": "John's iPhone",
                "device_type": "MOBILE",
                "platform": "IOS",
                "browser": "Safari"
            }
        }


class LoginRequest(BaseModel):
    """
    Login request schema.
    Supports both email and username for login.
    """
    email: EmailStr = Field(
        ...,
        description="User email address"
    )
    password: Annotated[str, Field(min_length=1)] = Field(
        ...,
        description="User password"
    )
    device_info: Optional[DeviceInfo] = Field(
        None,
        description="Device information for tracking"
    )
    remember_me: bool = Field(
        False,
        description="Extended session duration"
    )
    
    @validator('email')
    def normalize_email(cls, v: str) -> str:
        """Normalize email to lowercase."""
        return v.lower().strip()
    
    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "SecurePassword123!",
                "remember_me": False
            }
        }


class TokenResponse(BaseModel):
    """
    Token response schema for auth endpoints.
    """
    access_token: str = Field(
        ...,
        description="JWT access token"
    )
    refresh_token: Optional[str] = Field(
        None,
        description="JWT refresh token (optional)"
    )
    token_type: str = Field(
        "bearer",
        description="Token type (always 'bearer')"
    )
    expires_in: int = Field(
        ...,
        description="Token expiration time in seconds"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 3600
            }
        }


class LoginResponse(TokenResponse):
    """
    Login response schema extending TokenResponse.
    """
    user_id: str = Field(
        ...,
        description="User ID"
    )
    requires_2fa: bool = Field(
        False,
        description="Whether 2FA is required"
    )
    session_id: Optional[str] = Field(
        None,
        description="Temporary session ID for 2FA verification"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 3600,
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "requires_2fa": False
            }
        }


class RefreshTokenRequest(BaseModel):
    """
    Refresh token request schema.
    """
    refresh_token: str = Field(
        ...,
        description="JWT refresh token"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class LogoutRequest(BaseModel):
    """
    Logout request schema.
    """
    refresh_token: Optional[str] = Field(
        None,
        description="Refresh token to invalidate specific session"
    )
    all_sessions: bool = Field(
        False,
        description="Logout from all sessions/devices"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "all_sessions": False
            }
        }


class TwoFactorVerifyRequest(BaseModel):
    """
    Two-factor authentication verification request.
    """
    session_id: str = Field(
        ...,
        description="Temporary session ID from login response"
    )
    # code: constr(regex=r'^\d{6}$|^[A-Z0-9]{4}-[A-Z0-9]{4}$') = Field(
    #     ...,
    #     description="6-digit TOTP code or backup code (XXXX-XXXX format)"
    # )
    code: Annotated[str, Field(pattern=r'^\d{6}$|^[A-Z0-9]{4}-[A-Z0-9]{4}$')] = Field(
        ...,
        description="6-digit TOTP code or backup code (XXXX-XXXX format)"
    )
    method: TwoFactorMethod = Field(
        TwoFactorMethod.TOTP,
        description="2FA method being used"
    )
    trust_device: bool = Field(
        False,
        description="Whether to trust this device for future logins"
    )
    
    @validator('code')
    def normalize_code(cls, v: str) -> str:
        """Normalize code format."""
        # Remove spaces and uppercase for consistency
        return v.replace(" ", "").upper()
    
    class Config:
        use_enum_values = True
        schema_extra = {
            "example": {
                "session_id": "temp_session_123456",
                "code": "123456",
                "method": "TOTP",
                "trust_device": True
            }
        }


class TwoFactorSetupResponse(BaseModel):
    """
    Two-factor authentication setup response.
    """
    secret: str = Field(
        ...,
        description="Base32 encoded secret for TOTP"
    )
    qr_code: str = Field(
        ...,
        description="QR code as data URI for scanning"
    )
    backup_codes: List[str] = Field(
        ...,
        description="List of backup codes"
    )
    manual_entry_key: str = Field(
        ...,
        description="Manual entry key for TOTP apps"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "secret": "JBSWY3DPEHPK3PXP",
                "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANS...",
                "backup_codes": [
                    "ABCD-1234",
                    "EFGH-5678",
                    "IJKL-9012"
                ],
                "manual_entry_key": "JBSWY3DPEHPK3PXP"
            }
        }


class TwoFactorEnableRequest(BaseModel):
    """
    Request to enable two-factor authentication.
    """
    method: TwoFactorMethod = Field(
        TwoFactorMethod.TOTP,
        description="2FA method to enable"
    )
    # verification_code: constr(regex=r'^\d{6}$') = Field(
    #     ...,
    #     description="Verification code to confirm setup"
    # )
    verification_code: Annotated[str, Field(pattern=r'^\d{6}$')] = Field(
        ...,
        description="Verification code to confirm setup"
    )
    # phone_number: Optional[constr(regex=r'^\+?[1-9]\d{1,14}$')] = Field(
    #     None,
    #     description="Phone number for SMS method (E.164 format)"
    # )
    phone_number: Annotated[str, Field(pattern=r'^\+?[1-9]\d{1,14}$')] = Field(
        None,
        description="Phone number for SMS method (E.164 format)"
    )
    
    @validator('phone_number')
    def validate_phone_for_sms(cls, v: Optional[str], values: dict) -> Optional[str]:
        """Validate phone number is provided for SMS method."""
        if values.get('method') == TwoFactorMethod.SMS and not v:
            raise ValueError("Phone number is required for SMS 2FA method")
        return v
    
    class Config:
        use_enum_values = True
        schema_extra = {
            "example": {
                "method": "TOTP",
                "verification_code": "123456"
            }
        }


class SessionInfo(BaseModel):
    """
    Session information schema.
    """
    session_id: str = Field(
        ...,
        description="Session ID"
    )
    device_name: str = Field(
        ...,
        description="Device name"
    )
    device_type: Optional[str] = Field(
        None,
        description="Device type"
    )
    platform: Optional[str] = Field(
        None,
        description="Platform"
    )
    browser: Optional[str] = Field(
        None,
        description="Browser"
    )
    ip_address: Optional[str] = Field(
        None,
        description="IP address"
    )
    last_activity: datetime = Field(
        ...,
        description="Last activity timestamp"
    )
    created_at: datetime = Field(
        ...,
        description="Session creation timestamp"
    )
    is_current: bool = Field(
        False,
        description="Whether this is the current session"
    )
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        schema_extra = {
            "example": {
                "session_id": "550e8400-e29b-41d4-a716-446655440000",
                "device_name": "Chrome on Windows",
                "device_type": "DESKTOP",
                "platform": "WINDOWS",
                "browser": "Chrome",
                "ip_address": "192.168.1.1",
                "last_activity": "2024-01-15T10:30:00Z",
                "created_at": "2024-01-15T09:00:00Z",
                "is_current": True
            }
        }


class SessionListResponse(BaseModel):
    """
    List of active sessions response.
    """
    sessions: List[SessionInfo] = Field(
        ...,
        description="List of active sessions"
    )
    total: int = Field(
        ...,
        description="Total number of sessions"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "sessions": [
                    {
                        "session_id": "550e8400-e29b-41d4-a716-446655440000",
                        "device_name": "Chrome on Windows",
                        "device_type": "DESKTOP",
                        "platform": "WINDOWS",
                        "browser": "Chrome",
                        "ip_address": "192.168.1.1",
                        "last_activity": "2024-01-15T10:30:00Z",
                        "created_at": "2024-01-15T09:00:00Z",
                        "is_current": True
                    }
                ],
                "total": 1
            }
        }