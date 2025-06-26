"""
Generic response schemas untuk SecureAuth API.
Menangani response format yang konsisten.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field
from pydantic.generics import GenericModel


# Type variable untuk generic responses
T = TypeVar('T')


class MessageResponse(BaseModel):
    """
    Simple message response schema.
    """
    message: str = Field(
        ...,
        description="Response message"
    )
    details: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional details"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "message": "Operation completed successfully",
                "details": {
                    "affected_items": 1
                }
            }
        }


class ErrorResponse(BaseModel):
    """
    Error response schema dengan struktur konsisten.
    """
    error: Dict[str, Any] = Field(
        ...,
        description="Error details"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "error": {
                    "message": "Invalid request",
                    "type": "ValidationError",
                    "details": {
                        "field": "email",
                        "reason": "Invalid email format"
                    },
                    "request_id": "550e8400-e29b-41d4-a716-446655440000",
                    "timestamp": "2024-01-15T10:00:00Z"
                }
            }
        }


class ValidationErrorDetail(BaseModel):
    """
    Validation error detail schema.
    """
    field: str = Field(
        ...,
        description="Field name that failed validation"
    )
    message: str = Field(
        ...,
        description="Error message"
    )
    type: str = Field(
        ...,
        description="Error type"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "field": "email",
                "message": "Invalid email format",
                "type": "value_error"
            }
        }


class PaginationParams(BaseModel):
    """
    Pagination parameters schema.
    """
    page: int = Field(
        1,
        ge=1,
        description="Page number"
    )
    per_page: int = Field(
        20,
        ge=1,
        le=100,
        description="Items per page"
    )
    order_by: Optional[str] = Field(
        None,
        description="Field to order by"
    )
    order_direction: Optional[str] = Field(
        "asc",
        pattern="^(asc|desc)$",
        description="Order direction (asc/desc)"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "page": 1,
                "per_page": 20,
                "order_by": "created_at",
                "order_direction": "desc"
            }
        }


class PaginatedResponse(GenericModel, Generic[T]):
    """
    Generic paginated response schema.
    """
    items: List[T] = Field(
        ...,
        description="List of items"
    )
    total: int = Field(
        ...,
        description="Total number of items"
    )
    page: int = Field(
        ...,
        description="Current page"
    )
    per_page: int = Field(
        ...,
        description="Items per page"
    )
    pages: int = Field(
        ...,
        description="Total number of pages"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "items": [],
                "total": 100,
                "page": 1,
                "per_page": 20,
                "pages": 5
            }
        }


class HealthCheckResponse(BaseModel):
    """
    Health check response schema.
    """
    status: str = Field(
        ...,
        description="Health status"
    )
    timestamp: datetime = Field(
        ...,
        description="Check timestamp"
    )
    version: str = Field(
        ...,
        description="API version"
    )
    service: str = Field(
        ...,
        description="Service name"
    )
    details: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional health details"
    )
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2024-01-15T10:00:00Z",
                "version": "1.0.0",
                "service": "SecureAuth API",
                "details": {
                    "database": "connected",
                    "redis": "connected"
                }
            }
        }


class AuditLogResponse(BaseModel):
    """
    Audit log entry response schema.
    """
    al_id: UUID = Field(..., description="Audit log ID")
    al_user_id: Optional[UUID] = Field(None, description="User ID")
    al_action: str = Field(..., description="Action performed")
    al_entity_type: Optional[str] = Field(None, description="Entity type")
    al_entity_id: Optional[UUID] = Field(None, description="Entity ID")
    al_old_values: Optional[Dict[str, Any]] = Field(None, description="Old values")
    al_new_values: Optional[Dict[str, Any]] = Field(None, description="New values")
    al_ip_address: Optional[str] = Field(None, description="IP address")
    al_user_agent: Optional[str] = Field(None, description="User agent")
    created_at: datetime = Field(..., description="Timestamp")
    al_metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    
    # Computed fields
    changes: Optional[Dict[str, Dict[str, Any]]] = Field(None, description="Formatted changes")
    user: Optional[Dict[str, str]] = Field(None, description="User info")
    
    class Config:
        orm_mode = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            UUID: lambda v: str(v)
        }
        schema_extra = {
            "example": {
                "al_id": "550e8400-e29b-41d4-a716-446655440000",
                "al_user_id": "550e8400-e29b-41d4-a716-446655440001",
                "al_action": "LOGIN_SUCCESS",
                "al_entity_type": "USER",
                "al_entity_id": "550e8400-e29b-41d4-a716-446655440001",
                "al_old_values": None,
                "al_new_values": None,
                "al_ip_address": "192.168.1.1",
                "al_user_agent": "Mozilla/5.0...",
                "created_at": "2024-01-15T10:00:00Z",
                "al_metadata": {},
                "user": {
                    "username": "johndoe",
                    "email": "user@example.com"
                }
            }
        }


class DeviceResponse(BaseModel):
    """
    User device response schema.
    """
    ud_id: UUID = Field(..., description="Device ID")
    ud_device_id: str = Field(..., description="Device fingerprint")
    ud_device_name: Optional[str] = Field(None, description="Device name")
    ud_device_type: Optional[str] = Field(None, description="Device type")
    ud_platform: Optional[str] = Field(None, description="Platform")
    ud_browser: Optional[str] = Field(None, description="Browser")
    ud_is_trusted: bool = Field(..., description="Whether device is trusted")
    ud_last_used_at: Optional[datetime] = Field(None, description="Last used timestamp")
    created_at: datetime = Field(..., description="First seen timestamp")
    ud_is_active: bool = Field(..., description="Whether device is active")
    
    # Computed fields
    display_name: str = Field(..., description="Display name")
    is_mobile: bool = Field(..., description="Whether device is mobile")
    is_desktop: bool = Field(..., description="Whether device is desktop")
    is_recently_used: bool = Field(..., description="Used in last 7 days")
    
    class Config:
        orm_mode = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
            UUID: lambda v: str(v)
        }


class RateLimitResponse(BaseModel):
    """
    Rate limit information response.
    """
    limit: int = Field(
        ...,
        description="Request limit"
    )
    remaining: int = Field(
        ...,
        description="Remaining requests"
    )
    reset: int = Field(
        ...,
        description="Reset timestamp (Unix epoch)"
    )
    retry_after: Optional[int] = Field(
        None,
        description="Seconds until retry allowed"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "limit": 60,
                "remaining": 45,
                "reset": 1705315200,
                "retry_after": None
            }
        }