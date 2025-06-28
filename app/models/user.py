"""
User model untuk SecureAuth API.
Model utama yang merepresentasikan user dalam sistem.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer, JSON,
    UniqueConstraint, Index, CheckConstraint, text
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import relationship, Mapped
from sqlalchemy.ext.hybrid import hybrid_property

from app.db.base import BaseModel
from app.core.security import pwd_context

if TYPE_CHECKING:
    from app.models.session import UserSession
    from app.models.token import UserToken
    from app.models.audit import AuditLog
    from app.models.device import UserDevice
    from app.models.two_factor import TwoFactorAuth
    from app.models.password_history import PasswordHistory
    from app.models.login_attempt import LoginAttempt


class User(BaseModel):
    """
    User model untuk authentication dan user management.
    
    Attributes:
        u_id: Unique user ID (UUID)
        u_email: User's email address (unique)
        u_username: Username (unique)
        u_password_hash: Hashed password
        u_is_active: Whether user account is active
        u_is_verified: Whether email is verified
        u_is_locked: Whether account is locked
        u_email_verified_at: Timestamp when email was verified
        created_at: Account creation timestamp
        updated_at: Last update timestamp
        u_last_login_at: Last successful login timestamp
        u_failed_login_attempts: Number of consecutive failed login attempts
        u_locked_until: Account locked until this timestamp
        u_metadata: Additional user metadata (JSONB)
        u_ip_address: IP address during registration
        u_user_agent: User agent during registration
    """
    
    __tablename__ = "users"
    
    # Primary key
    u_id = Column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        server_default=text("uuid_generate_v4()"),
        nullable=False,
        index=True
    )
    
    # Authentication fields
    u_email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    u_username = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True
    )
    u_password_hash = Column(
        String(255),
        nullable=False
    )
    
    # Status fields
    u_is_active = Column(
        Boolean,
        default=True,
        nullable=False,
        index=True
    )
    u_is_verified = Column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )
    u_is_locked = Column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )
    
    # Timestamps
    u_email_verified_at = Column(
        DateTime(timezone=True),
        nullable=True
    )
    # created_at = Column(
    #     DateTime(timezone=True),
    #     server_default=text("CURRENT_TIMESTAMP"),
    #     nullable=False,
    #     index=True
    # )
    # updated_at = Column(
    #     DateTime(timezone=True),
    #     onupdate=lambda: datetime.now(timezone.utc),
    #     nullable=True
    # )
    u_last_login_at = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True
    )
    
    # Security fields
    u_failed_login_attempts = Column(
        Integer,
        default=0,
        nullable=False
    )
    u_locked_until = Column(
        DateTime(timezone=True),
        nullable=True,
        index=True
    )
    
    # Metadata fields
    u_metadata = Column(
        JSON,
        nullable=True,
        default=dict
    )
    u_ip_address = Column(
        String(45),  # Supports both IPv4 and IPv6
        nullable=True
    )
    u_user_agent = Column(
        String,  # TEXT type
        nullable=True
    )
    
    # Relationships
    sessions: Mapped[List["UserSession"]] = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    
    tokens: Mapped[List["UserToken"]] = relationship(
        "UserToken",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    
    devices: Mapped[List["UserDevice"]] = relationship(
        "UserDevice",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    
    two_factor_auth: Mapped[Optional["TwoFactorAuth"]] = relationship(
        "TwoFactorAuth",
        back_populates="user",
        cascade="all, delete-orphan",
        uselist=False,
        lazy="joined"
    )
    
    password_history: Mapped[List["PasswordHistory"]] = relationship(
        "PasswordHistory",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="desc(PasswordHistory.created_at)"
    )
    
    login_attempts: Mapped[List["LoginAttempt"]] = relationship(
        "LoginAttempt",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
        order_by="desc(LoginAttempt.la_attempted_at)"
    )
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('u_email', name='uq_users_email'),
        UniqueConstraint('u_username', name='uq_users_username'),
        CheckConstraint('length(u_email) >= 3', name='ck_users_email_length'),
        CheckConstraint('length(u_username) >= 3', name='ck_users_username_length'),
        Index('idx_users_is_active', 'u_is_active'),
        Index('idx_users_is_verified', 'u_is_verified'),
        Index('idx_users_is_locked', 'u_is_locked'),
    )
    
    # Properties
    @hybrid_property
    def is_locked_now(self) -> bool:
        """
        Check if user is currently locked.
        Takes into account both u_is_locked flag and u_locked_until timestamp.
        """
        if not self.u_is_locked:
            return False
        
        if self.u_locked_until:
            return datetime.now(timezone.utc) < self.u_locked_until
        
        return True
    
    @property
    def full_identifier(self) -> str:
        """Get full user identifier (username or email)."""
        return self.u_username or self.u_email
    
    @property
    def display_name(self) -> str:
        """Get display name for user."""
        if self.u_metadata and "display_name" in self.u_metadata:
            return self.u_metadata["display_name"]
        return self.u_username
    
    @property
    def has_2fa_enabled(self) -> bool:
        """Check if user has 2FA enabled."""
        return bool(self.two_factor_auth and self.two_factor_auth.tfa_is_enabled)
    
    # Methods
    def set_password(self, password: str) -> None:
        """
        Set user password (hashes it).
        
        Args:
            password: Plain text password
        """
        self.u_password_hash = pwd_context.hash(password)
    
    def verify_password(self, password: str) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Plain text password to verify
            
        Returns:
            True if password matches
        """
        return pwd_context.verify(password, self.u_password_hash)
    
    def update_last_login(self, commit: bool = True) -> None:
        """
        Update last login timestamp.
        
        Args:
            commit: Whether to commit the change
        """
        self.u_last_login_at = datetime.now(timezone.utc)
        self.u_failed_login_attempts = 0
        
    def increment_failed_login_attempts(self) -> int:
        """
        Increment failed login attempts counter.
        
        Returns:
            New failed attempts count
        """
        self.u_failed_login_attempts += 1
        return self.u_failed_login_attempts
    
    def lock_account(self, until: datetime) -> None:
        """
        Lock user account until specified time.
        
        Args:
            until: Lock expiration timestamp
        """
        self.u_is_locked = True
        self.u_locked_until = until
    
    def unlock_account(self) -> None:
        """Unlock user account."""
        self.u_is_locked = False
        self.u_locked_until = None
        self.u_failed_login_attempts = 0
    
    def verify_email(self) -> None:
        """Mark email as verified."""
        self.u_is_verified = True
        self.u_email_verified_at = datetime.now(timezone.utc)
    
    def update_metadata(self, key: str, value: Any) -> None:
        """
        Update metadata field.
        
        Args:
            key: Metadata key
            value: Metadata value
        """
        if not self.u_metadata:
            self.u_metadata = {}
        self.u_metadata[key] = value
    
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        Get metadata value.
        
        Args:
            key: Metadata key
            default: Default value if key not found
            
        Returns:
            Metadata value or default
        """
        if not self.u_metadata:
            return default
        return self.u_metadata.get(key, default)
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert user to dictionary.
        
        Args:
            include_sensitive: Include sensitive fields
            
        Returns:
            User dictionary
        """
        data = {
            "u_id": str(self.u_id),
            "u_email": self.u_email,
            "u_username": self.u_username,
            "u_is_active": self.u_is_active,
            "u_is_verified": self.u_is_verified,
            "u_is_locked": self.is_locked_now,
            "u_email_verified_at": self.u_email_verified_at.isoformat() if self.u_email_verified_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "u_last_login_at": self.u_last_login_at.isoformat() if self.u_last_login_at else None,
            "u_metadata": self.u_metadata,
            "has_2fa_enabled": self.has_2fa_enabled
        }
        
        if include_sensitive:
            data.update({
                "u_failed_login_attempts": self.u_failed_login_attempts,
                "u_locked_until": self.u_locked_until.isoformat() if self.u_locked_until else None,
                "u_ip_address": self.u_ip_address,
                "u_user_agent": self.u_user_agent
            })
        
        return data
    
    def __repr__(self) -> str:
        """String representation."""
        return f"<User(id={self.u_id}, email={self.u_email}, username={self.u_username})>"