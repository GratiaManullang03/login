"""
User session model untuk SecureAuth API.
Mengelola active sessions dan refresh tokens.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
    Column, String, Boolean, DateTime, ForeignKey, JSON,
    Index, text
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import relationship, Mapped

from app.db.base import BaseModel

if TYPE_CHECKING:
    from app.models.user import User


class UserSession(BaseModel):
    """
    User session model untuk tracking active sessions.
    
    Setiap login berhasil akan membuat session baru dengan refresh token.
    Session digunakan untuk melacak device, logout, dan session management.
    
    Attributes:
        us_id: Session ID (UUID)
        us_user_id: User ID yang memiliki session
        us_refresh_token_hash: Hash dari refresh token
        us_expires_at: Session expiration timestamp
        us_ip_address: IP address saat session dibuat
        us_user_agent: User agent saat session dibuat
        us_device_info: Additional device information (JSONB)
        us_is_active: Whether session is still active
        us_created_at: Session creation timestamp
        us_last_activity: Last activity timestamp
        us_logout_reason: Reason for logout (if logged out)
    """
    
    __tablename__ = "user_sessions"
    
    # Primary key
    us_id = Column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        server_default=text("uuid_generate_v4()"),
        nullable=False,
        index=True
    )
    
    # Foreign key
    us_user_id = Column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.u_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Session fields
    us_refresh_token_hash = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    us_expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True
    )
    
    # Tracking fields
    us_ip_address = Column(
        String(45),
        nullable=True
    )
    us_user_agent = Column(
        String,  # TEXT type
        nullable=True
    )
    us_device_info = Column(
        JSON,
        nullable=True,
        default=dict
    )
    
    # Status fields
    us_is_active = Column(
        Boolean,
        default=True,
        nullable=False,
        index=True
    )
    us_created_at = Column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
        index=True
    )
    us_last_activity = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True
    )
    us_logout_reason = Column(
        String(255),
        nullable=True
    )
    
    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="sessions",
        lazy="joined"
    )
    
    # Indexes
    __table_args__ = (
        Index('idx_user_sessions_user_id', 'us_user_id'),
        Index('idx_user_sessions_is_active', 'us_is_active'),
        Index('idx_user_sessions_expires_at', 'us_expires_at'),
    )
    
    # Properties
    @property
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.now(timezone.utc) > self.us_expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if session is valid (active and not expired)."""
        return self.us_is_active and not self.is_expired
    
    @property
    def device_name(self) -> Optional[str]:
        """Get device name from device info."""
        if self.us_device_info:
            return self.us_device_info.get("device_name")
        return None
    
    @property
    def device_type(self) -> Optional[str]:
        """Get device type from device info."""
        if self.us_device_info:
            return self.us_device_info.get("device_type")
        return None
    
    @property
    def platform(self) -> Optional[str]:
        """Get platform from device info."""
        if self.us_device_info:
            return self.us_device_info.get("platform")
        return None
    
    # Methods
    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.us_last_activity = datetime.now(timezone.utc)
    
    def terminate(self, reason: str = "USER_INITIATED") -> None:
        """
        Terminate session.
        
        Args:
            reason: Reason for termination
        """
        self.us_is_active = False
        self.us_logout_reason = reason
    
    def extend_expiration(self, new_expires_at: datetime) -> None:
        """
        Extend session expiration.
        
        Args:
            new_expires_at: New expiration timestamp
        """
        if new_expires_at > self.us_expires_at:
            self.us_expires_at = new_expires_at
    
    def update_device_info(self, device_info: Dict[str, Any]) -> None:
        """
        Update device information.
        
        Args:
            device_info: New device information
        """
        if not self.us_device_info:
            self.us_device_info = {}
        self.us_device_info.update(device_info)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert session to dictionary.
        
        Returns:
            Session dictionary
        """
        return {
            "us_id": str(self.us_id),
            "us_user_id": str(self.us_user_id),
            "us_expires_at": self.us_expires_at.isoformat(),
            "us_ip_address": self.us_ip_address,
            "us_user_agent": self.us_user_agent,
            "us_device_info": self.us_device_info,
            "us_is_active": self.us_is_active,
            "us_created_at": self.us_created_at.isoformat() if self.us_created_at else None,
            "us_last_activity": self.us_last_activity.isoformat() if self.us_last_activity else None,
            "us_logout_reason": self.us_logout_reason,
            "is_expired": self.is_expired,
            "is_valid": self.is_valid,
            "device_name": self.device_name,
            "device_type": self.device_type,
            "platform": self.platform
        }
    
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<UserSession(id={self.us_id}, user_id={self.us_user_id}, "
            f"active={self.us_is_active}, expires={self.us_expires_at})>"
        )