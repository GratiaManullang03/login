"""
Token schemas untuk SecureAuth API.
Menangani validasi untuk berbagai jenis token operations.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.core.constants import TokenType


class TokenBase(BaseModel):
    """
    Base token schema.
    """
    token_type: TokenType = Field(
        ...,
        description="Type of token"
    )
    
    class Config:
        use_enum_values = True


class TokenCreate(TokenBase):
    """
    Token creation request schema.
    """
    user_id: UUID = Field(
        ...,
        description="User ID for token"
    )
    expires_in_seconds: Optional[int] = Field(
        None,
        description="Custom expiration time in seconds"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional token metadata"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "user_id": "550e8400-e29b-41d4-a716-446655440000",
                "token_type": "EMAIL_VERIFICATION",
                "expires_in_seconds": 86400,
                "metadata": {
                    "purpose": "Account activation"
                }
            }
        }


class TokenResponse(BaseModel):
    """
    Token response schema dengan detail informasi.
    """
    ut_id: UUID = Field(..., description="Token ID")
    ut_user_id: UUID = Field(..., description="User ID")
    ut_token_type: str = Field(..., description="Token type")
    ut_expires_at: datetime = Field(..., description="Expiration timestamp")
    ut_is_used: bool = Field(..., description="Whether token has been used")
    ut_used_at: Optional[datetime] = Field(None, description="When token was used")
    created_at: datetime = Field(..., description="Creation timestamp")
    ut_metadata: Optional[Dict[str, Any]] = Field(None, description="Token metadata")
    is_expired: bool = Field(..., description="Whether token is expired")
    is_valid: bool = Field(..., description="Whether token is valid")
    
    class Config:
        orm_mode = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            UUID: lambda v: str(v)
        }
        schema_extra = {
            "example": {
                "ut_id": "550e8400-e29b-41d4-a716-446655440000",
                "ut_user_id": "550e8400-e29b-41d4-a716-446655440001",
                "ut_token_type": "EMAIL_VERIFICATION",
                "ut_expires_at": "2024-01-16T00:00:00Z",
                "ut_is_used": False,
                "ut_used_at": None,
                "created_at": "2024-01-15T00:00:00Z",
                "ut_metadata": {},
                "is_expired": False,
                "is_valid": True
            }
        }


class TokenVerify(BaseModel):
    """
    Token verification request schema.
    """
    token: str = Field(
        ...,
        description="Token to verify"
    )
    token_type: TokenType = Field(
        ...,
        description="Expected token type"
    )
    
    class Config:
        use_enum_values = True
        schema_extra = {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "EMAIL_VERIFICATION"
            }
        }


class TokenListResponse(BaseModel):
    """
    List of tokens response.
    """
    tokens: List[TokenResponse] = Field(
        ...,
        description="List of tokens"
    )
    total: int = Field(
        ...,
        description="Total number of tokens"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "tokens": [],
                "total": 0
            }
        }


class APIKeyCreate(BaseModel):
    """
    API key creation request schema.
    """
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="API key name/description"
    )
    expires_in_days: Optional[int] = Field(
        None,
        ge=1,
        le=365,
        description="Expiration in days (max 365)"
    )
    scopes: Optional[List[str]] = Field(
        None,
        description="API key scopes/permissions"
    )
    
    @field_validator('name')
    def validate_name(cls, v: str) -> str:
        """Validate API key name."""
        return v.strip()
    
    class Config:
        schema_extra = {
            "example": {
                "name": "Production API Key",
                "expires_in_days": 90,
                "scopes": ["read:users", "write:users"]
            }
        }


class APIKeyResponse(BaseModel):
    """
    API key response schema.
    """
    key_id: UUID = Field(..., description="API key ID")
    name: str = Field(..., description="API key name")
    key: Optional[str] = Field(None, description="API key (only shown once)")
    created_at: datetime = Field(..., description="Creation timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    last_used_at: Optional[datetime] = Field(None, description="Last usage timestamp")
    is_active: bool = Field(..., description="Whether key is active")
    scopes: Optional[List[str]] = Field(None, description="API key scopes")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            UUID: lambda v: str(v)
        }
        schema_extra = {
            "example": {
                "key_id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "Production API Key",
                "key": "sk_live_abcdef123456...",
                "created_at": "2024-01-15T00:00:00Z",
                "expires_at": "2024-04-15T00:00:00Z",
                "last_used_at": None,
                "is_active": True,
                "scopes": ["read:users", "write:users"]
            }
        }