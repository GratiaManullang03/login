"""
User device model untuk SecureAuth API.
Melacak device yang digunakan user untuk mengakses sistem.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
    Column, String, Boolean, DateTime, ForeignKey,
    Index, text, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import relationship, Mapped

from app.db.base import BaseModel
from app.core.constants import DeviceType, Platform

if TYPE_CHECKING:
    from app.models.user import User


class UserDevice(BaseModel):
    """
    User device model untuk device tracking dan trust.
    
    Melacak semua device yang digunakan user untuk login.
    Device dapat di-trust untuk skip 2FA pada device tersebut.
    
    Attributes:
        ud_id: Device record ID (UUID)
        ud_user_id: User ID yang memiliki device
        ud_device_id: Unique device identifier/fingerprint
        ud_device_name: Human readable device name
        ud_device_type: Type of device (Mobile, Desktop, etc)
        ud_platform: Platform (iOS, Android, Windows, etc)
        ud_browser: Browser name
        ud_is_trusted: Whether device is trusted
        ud_last_used_at: Last time device was used
        created_at: When device was first seen
        ud_is_active: Whether device is still active
    """
    
    __tablename__ = "user_devices"
    
    # Primary key
    ud_id = Column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        server_default=text("uuid_generate_v4()"),
        nullable=False,
        index=True
    )
    
    # Foreign key
    ud_user_id = Column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.u_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Device identification
    ud_device_id = Column(
        String(255),
        nullable=False,
        index=True
    )
    ud_device_name = Column(
        String(255),
        nullable=True
    )
    
    # Device info
    ud_device_type = Column(
        String(100),
        nullable=True
    )
    ud_platform = Column(
        String(100),
        nullable=True
    )
    ud_browser = Column(
        String(100),
        nullable=True
    )
    
    # Trust and status
    ud_is_trusted = Column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )
    ud_last_used_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
        index=True
    )
    ud_is_active = Column(
        Boolean,
        default=True,
        nullable=False,
        index=True
    )
    
    # Additional metadata
    ud_metadata = Column(
        String,  # JSON type
        nullable=True
    )
    
    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="devices",
        lazy="joined"
    )
    
    # Constraints and indexes
    __table_args__ = (
        # Composite index for user + device lookup
        Index('idx_user_devices_user_device', 'ud_user_id', 'ud_device_id'),
        Index('idx_user_devices_is_trusted', 'ud_is_trusted'),
        Index('idx_user_devices_is_active', 'ud_is_active'),
    )
    
    # Properties
    @property
    def display_name(self) -> str:
        """Get display name for device."""
        if self.ud_device_name:
            return self.ud_device_name
        
        # Generate from device info
        parts = []
        if self.ud_platform:
            parts.append(self.ud_platform)
        if self.ud_device_type:
            parts.append(self.ud_device_type)
        if self.ud_browser:
            parts.append(self.ud_browser)
        
        return " ".join(parts) if parts else "Unknown Device"
    
    @property
    def is_mobile(self) -> bool:
        """Check if device is mobile."""
        return self.ud_device_type == DeviceType.MOBILE
    
    @property
    def is_desktop(self) -> bool:
        """Check if device is desktop."""
        return self.ud_device_type == DeviceType.DESKTOP
    
    @property
    def is_recently_used(self) -> bool:
        """Check if device was used in last 7 days."""
        if not self.ud_last_used_at:
            return False
        
        days_since = (datetime.now(timezone.utc) - self.ud_last_used_at).days
        return days_since <= 7
    
    # Methods
    def update_last_used(self) -> None:
        """Update last used timestamp."""
        self.ud_last_used_at = datetime.now(timezone.utc)
    
    def trust_device(self) -> None:
        """Mark device as trusted."""
        self.ud_is_trusted = True
    
    def untrust_device(self) -> None:
        """Remove trust from device."""
        self.ud_is_trusted = False
    
    def deactivate(self) -> None:
        """Deactivate device."""
        self.ud_is_active = False
        self.ud_is_trusted = False
    
    def reactivate(self) -> None:
        """Reactivate device."""
        self.ud_is_active = True
    
    def update_device_info(
        self,
        device_type: Optional[str] = None,
        platform: Optional[str] = None,
        browser: Optional[str] = None,
        device_name: Optional[str] = None
    ) -> None:
        """
        Update device information.
        
        Args:
            device_type: New device type
            platform: New platform
            browser: New browser
            device_name: New device name
        """
        if device_type:
            self.ud_device_type = device_type
        if platform:
            self.ud_platform = platform
        if browser:
            self.ud_browser = browser
        if device_name:
            self.ud_device_name = device_name
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert device to dictionary.
        
        Returns:
            Device dictionary
        """
        return {
            "ud_id": str(self.ud_id),
            "ud_user_id": str(self.ud_user_id),
            "ud_device_id": self.ud_device_id,
            "ud_device_name": self.ud_device_name,
            "ud_device_type": self.ud_device_type,
            "ud_platform": self.ud_platform,
            "ud_browser": self.ud_browser,
            "ud_is_trusted": self.ud_is_trusted,
            "ud_last_used_at": self.ud_last_used_at.isoformat() if self.ud_last_used_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "ud_is_active": self.ud_is_active,
            "display_name": self.display_name,
            "is_mobile": self.is_mobile,
            "is_desktop": self.is_desktop,
            "is_recently_used": self.is_recently_used
        }
    
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<UserDevice(id={self.ud_id}, user_id={self.ud_user_id}, "
            f"device_id={self.ud_device_id}, trusted={self.ud_is_trusted})>"
        )