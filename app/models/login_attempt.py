"""
Login attempt model untuk SecureAuth API.
Melacak semua percobaan login untuk security monitoring.
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

from app.db.base import Base
from app.core.constants import LoginFailureReason

if TYPE_CHECKING:
    from app.models.user import User


class LoginAttempt(Base):
    """
    Login attempt model untuk tracking semua login attempts.
    
    Mencatat baik login yang berhasil maupun gagal untuk:
    - Security monitoring
    - Brute force detection
    - Audit trail
    - User activity tracking
    
    Attributes:
        la_id: Login attempt ID (UUID)
        la_user_id: User ID (nullable jika email tidak ditemukan)
        la_email: Email yang digunakan untuk login
        la_ip_address: IP address dari login attempt
        la_user_agent: User agent string
        la_success: Whether login was successful
        la_failure_reason: Reason for failure (if failed)
        la_metadata: Additional metadata (JSONB)
        la_attempted_at: Timestamp of attempt
    """
    
    __tablename__ = "login_attempts"
    
    # Primary key
    la_id = Column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        server_default=text("uuid_generate_v4()"),
        nullable=False,
        index=True
    )
    
    # Foreign key (nullable)
    la_user_id = Column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.u_id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    
    # Login info
    la_email = Column(
        String(255),
        nullable=False,
        index=True
    )
    la_ip_address = Column(
        String(45),
        nullable=True,
        index=True
    )
    la_user_agent = Column(
        String,  # TEXT type
        nullable=True
    )
    
    # Result
    la_success = Column(
        Boolean,
        nullable=False,
        index=True
    )
    la_failure_reason = Column(
        String(255),
        nullable=True
    )
    
    # Metadata and timestamp
    la_metadata = Column(
        JSON,
        nullable=True,
        default=dict
    )
    la_attempted_at = Column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
        index=True
    )
    
    # Relationships
    user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="login_attempts",
        lazy="joined"
    )
    
    # Indexes
    __table_args__ = (
        Index('idx_login_attempts_user_id', 'la_user_id'),
        Index('idx_login_attempts_email', 'la_email'),
        Index('idx_login_attempts_ip_address', 'la_ip_address'),
        Index('idx_login_attempts_success', 'la_success'),
        Index('idx_login_attempts_attempted_at', 'la_attempted_at'),
    )
    
    # Properties
    @property
    def is_successful(self) -> bool:
        """Check if login was successful."""
        return self.la_success
    
    @property
    def is_failed(self) -> bool:
        """Check if login failed."""
        return not self.la_success
    
    @property
    def is_invalid_credentials(self) -> bool:
        """Check if failure was due to invalid credentials."""
        return self.la_failure_reason == LoginFailureReason.INVALID_CREDENTIALS
    
    @property
    def is_account_locked(self) -> bool:
        """Check if failure was due to locked account."""
        return self.la_failure_reason == LoginFailureReason.ACCOUNT_LOCKED
    
    @property
    def is_rate_limited(self) -> bool:
        """Check if failure was due to rate limiting."""
        return self.la_failure_reason == LoginFailureReason.RATE_LIMITED
    
    @property
    def device_info(self) -> Optional[Dict[str, Any]]:
        """Get device info from metadata."""
        if self.la_metadata:
            return self.la_metadata.get("device_info")
        return None
    
    @property
    def location_info(self) -> Optional[Dict[str, Any]]:
        """Get location info from metadata."""
        if self.la_metadata:
            return self.la_metadata.get("location")
        return None
    
    # Methods
    @classmethod
    def create_successful(
        cls,
        user_id: UUID,
        email: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "LoginAttempt":
        """
        Create successful login attempt record.
        
        Args:
            user_id: User ID
            email: Email used
            ip_address: Client IP
            user_agent: User agent string
            metadata: Additional metadata
            
        Returns:
            New LoginAttempt instance
        """
        return cls(
            la_user_id=user_id,
            la_email=email,
            la_ip_address=ip_address,
            la_user_agent=user_agent,
            la_success=True,
            la_metadata=metadata or {}
        )
    
    @classmethod
    def create_failed(
        cls,
        email: str,
        failure_reason: str,
        user_id: Optional[UUID] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "LoginAttempt":
        """
        Create failed login attempt record.
        
        Args:
            email: Email used
            failure_reason: Reason for failure
            user_id: User ID (if user exists)
            ip_address: Client IP
            user_agent: User agent string
            metadata: Additional metadata
            
        Returns:
            New LoginAttempt instance
        """
        return cls(
            la_user_id=user_id,
            la_email=email,
            la_ip_address=ip_address,
            la_user_agent=user_agent,
            la_success=False,
            la_failure_reason=failure_reason,
            la_metadata=metadata or {}
        )
    
    def add_metadata(self, key: str, value: Any) -> None:
        """
        Add metadata to login attempt.
        
        Args:
            key: Metadata key
            value: Metadata value
        """
        if not self.la_metadata:
            self.la_metadata = {}
        self.la_metadata[key] = value
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary.
        
        Returns:
            Dictionary representation
        """
        return {
            "la_id": str(self.la_id),
            "la_user_id": str(self.la_user_id) if self.la_user_id else None,
            "la_email": self.la_email,
            "la_ip_address": self.la_ip_address,
            "la_user_agent": self.la_user_agent,
            "la_success": self.la_success,
            "la_failure_reason": self.la_failure_reason,
            "la_metadata": self.la_metadata,
            "la_attempted_at": self.la_attempted_at.isoformat() if self.la_attempted_at else None,
            "is_successful": self.is_successful,
            "is_failed": self.is_failed
        }
    
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<LoginAttempt(id={self.la_id}, email={self.la_email}, "
            f"success={self.la_success}, attempted_at={self.la_attempted_at})>"
        )