"""
Password history model untuk SecureAuth API.
Melacak riwayat password untuk mencegah penggunaan ulang.
"""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, List
from uuid import UUID

from sqlalchemy import (
    Column, DateTime, ForeignKey, String,
    Index, text
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import relationship, Mapped

from app.db.base import Base
from app.core.security import pwd_context

if TYPE_CHECKING:
    from app.models.user import User


class PasswordHistory(Base):
    """
    Password history model untuk tracking password lama.
    
    Mencegah user menggunakan kembali password yang sudah pernah dipakai.
    Hanya menyimpan hash, tidak ada plain text password.
    
    Attributes:
        ph_id: Password history ID (UUID)
        ph_user_id: User ID yang memiliki password
        ph_password_hash: Hash dari password lama
        ph_created_at: When password was created/used
    """
    
    __tablename__ = "password_history"
    
    # Primary key
    ph_id = Column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        server_default=text("uuid_generate_v4()"),
        nullable=False,
        index=True
    )
    
    # Foreign key
    ph_user_id = Column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.u_id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    
    # Password hash
    ph_password_hash = Column(
        String(255),
        nullable=False
    )
    
    # Timestamp
    ph_created_at = Column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
        index=True
    )
    
    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="password_history",
        lazy="joined"
    )
    
    # Indexes
    __table_args__ = (
        Index('idx_password_history_user_id', 'ph_user_id'),
        Index('idx_password_history_created_at', 'ph_created_at'),
    )
    
    # Methods
    def check_password(self, password: str) -> bool:
        """
        Check if password matches this historical password.
        
        Args:
            password: Plain text password to check
            
        Returns:
            True if password matches
        """
        return pwd_context.verify(password, self.ph_password_hash)
    
    @staticmethod
    def check_password_reuse(
        user_id: UUID,
        password: str,
        history_entries: List["PasswordHistory"]
    ) -> bool:
        """
        Check if password has been used before by user.
        
        Args:
            user_id: User ID to check
            password: Plain text password to check
            history_entries: List of password history entries
            
        Returns:
            True if password has been used before
        """
        for entry in history_entries:
            if entry.ph_user_id == user_id and entry.check_password(password):
                return True
        return False
    
    @classmethod
    def create_from_password(cls, user_id: UUID, password: str) -> "PasswordHistory":
        """
        Create new password history entry.
        
        Args:
            user_id: User ID
            password: Plain text password
            
        Returns:
            New PasswordHistory instance
        """
        return cls(
            ph_user_id=user_id,
            ph_password_hash=pwd_context.hash(password)
        )
    
    def to_dict(self) -> dict:
        """
        Convert to dictionary.
        
        Returns:
            Dictionary representation
        """
        return {
            "ph_id": str(self.ph_id),
            "ph_user_id": str(self.ph_user_id),
            "ph_created_at": self.ph_created_at.isoformat() if self.ph_created_at else None
        }
    
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<PasswordHistory(id={self.ph_id}, user_id={self.ph_user_id}, "
            f"created_at={self.ph_created_at})>"
        )