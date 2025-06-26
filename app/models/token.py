"""
User token model untuk SecureAuth API.
Mengelola berbagai jenis token seperti email verification, password reset, dll.
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
from app.core.constants import TokenType

if TYPE_CHECKING:
    from app.models.user import User


class UserToken(BaseModel):
    """
    User token model untuk berbagai keperluan authentication.
    
    Token digunakan untuk:
    - Email verification
    - Password reset
    - Two-factor authentication
    - API keys
    
    Attributes:
        ut_id: Token ID (UUID)
        ut_user_id: User ID yang memiliki token
        ut_token_hash: Hash dari token value
        ut_token_type: Tipe token (EMAIL_VERIFICATION, PASSWORD_RESET, etc)
        ut_expires_at: Token expiration timestamp
        ut_is_used: Whether token has been used
        ut_used_at: Timestamp when token was used
        ut_metadata: Additional token metadata (JSONB)
        created_at: Token creation timestamp
    """
    
    __tablename__ = "user_tokens"
    
    # Primary key
    ut_id = Column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        server_default=text("uuid_generate_v4()"),
        nullable=False,
        index=True
    )
    
    # Foreign key
    ut_user_id = Column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.u_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Token fields
    ut_token_hash = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    ut_token_type = Column(
        String(50),
        nullable=False,
        index=True
    )
    ut_expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True
    )
    
    # Status fields
    ut_is_used = Column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )
    ut_used_at = Column(
        DateTime(timezone=True),
        nullable=True
    )
    
    # Metadata
    ut_metadata = Column(
        JSON,
        nullable=True,
        default=dict
    )
    created_at = Column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
        index=True
    )
    
    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="tokens",
        lazy="joined"
    )
    
    # Indexes
    __table_args__ = (
        Index('idx_user_tokens_user_id', 'ut_user_id'),
        Index('idx_user_tokens_token_type', 'ut_token_type'),
        Index('idx_user_tokens_is_used', 'ut_is_used'),
        Index('idx_user_tokens_expires_at', 'ut_expires_at'),
    )
    
    # Properties
    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.now(timezone.utc) > self.ut_expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if token is valid (not used and not expired)."""
        return not self.ut_is_used and not self.is_expired
    
    @property
    def is_email_verification(self) -> bool:
        """Check if token is for email verification."""
        return self.ut_token_type == TokenType.EMAIL_VERIFICATION
    
    @property
    def is_password_reset(self) -> bool:
        """Check if token is for password reset."""
        return self.ut_token_type == TokenType.PASSWORD_RESET
    
    @property
    def is_two_factor_auth(self) -> bool:
        """Check if token is for 2FA."""
        return self.ut_token_type == TokenType.TWO_FACTOR_AUTH
    
    @property
    def is_api_key(self) -> bool:
        """Check if token is an API key."""
        return self.ut_token_type == TokenType.API_KEY
    
    # Methods
    def mark_as_used(self) -> None:
        """Mark token as used."""
        self.ut_is_used = True
        self.ut_used_at = datetime.now(timezone.utc)
    
    def extend_expiration(self, new_expires_at: datetime) -> None:
        """
        Extend token expiration.
        
        Args:
            new_expires_at: New expiration timestamp
        """
        if new_expires_at > self.ut_expires_at:
            self.ut_expires_at = new_expires_at
    
    def update_metadata(self, key: str, value: Any) -> None:
        """
        Update metadata field.
        
        Args:
            key: Metadata key
            value: Metadata value
        """
        if not self.ut_metadata:
            self.ut_metadata = {}
        self.ut_metadata[key] = value
    
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        Get metadata value.
        
        Args:
            key: Metadata key
            default: Default value if key not found
            
        Returns:
            Metadata value or default
        """
        if not self.ut_metadata:
            return default
        return self.ut_metadata.get(key, default)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert token to dictionary.
        
        Returns:
            Token dictionary
        """
        return {
            "ut_id": str(self.ut_id),
            "ut_user_id": str(self.ut_user_id),
            "ut_token_type": self.ut_token_type,
            "ut_expires_at": self.ut_expires_at.isoformat(),
            "ut_is_used": self.ut_is_used,
            "ut_used_at": self.ut_used_at.isoformat() if self.ut_used_at else None,
            "ut_metadata": self.ut_metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "is_expired": self.is_expired,
            "is_valid": self.is_valid
        }
    
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<UserToken(id={self.ut_id}, user_id={self.ut_user_id}, "
            f"type={self.ut_token_type}, valid={self.is_valid})>"
        )