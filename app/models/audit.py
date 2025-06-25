"""
Audit log model untuk SecureAuth API.
Mencatat semua perubahan penting dalam sistem untuk audit trail.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, TYPE_CHECKING
from uuid import UUID

from sqlalchemy import (
    Column, String, DateTime, ForeignKey, JSON,
    Index, text
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import relationship, Mapped

from app.db.base import Base  # Use Base instead of BaseModel for audit logs
from app.core.constants import AuditAction, EntityType

if TYPE_CHECKING:
    from app.models.user import User


class AuditLog(Base):
    """
    Audit log model untuk tracking semua perubahan penting.
    
    Audit logs tidak di-update atau delete, hanya insert.
    Logs tetap ada meskipun user dihapus (SET NULL).
    
    Attributes:
        al_id: Audit log ID (UUID)
        al_user_id: User ID yang melakukan action (nullable)
        al_action: Action yang dilakukan
        al_entity_type: Tipe entity yang diubah
        al_entity_id: ID entity yang diubah
        al_old_values: Nilai lama (JSONB)
        al_new_values: Nilai baru (JSONB)
        al_ip_address: IP address saat action
        al_user_agent: User agent saat action
        al_created_at: Timestamp audit log
    """
    
    __tablename__ = "audit_logs"
    
    # Primary key
    al_id = Column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        server_default=text("uuid_generate_v4()"),
        nullable=False,
        index=True
    )
    
    # Foreign key (nullable untuk preserve logs)
    al_user_id = Column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.u_id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    
    # Audit fields
    al_action = Column(
        String(100),
        nullable=False,
        index=True
    )
    al_entity_type = Column(
        String(100),
        nullable=True,
        index=True
    )
    al_entity_id = Column(
        PostgresUUID(as_uuid=True),
        nullable=True,
        index=True
    )
    
    # Change tracking
    al_old_values = Column(
        JSON,
        nullable=True
    )
    al_new_values = Column(
        JSON,
        nullable=True
    )
    
    # Context fields
    al_ip_address = Column(
        String(45),
        nullable=True
    )
    al_user_agent = Column(
        String,  # TEXT type
        nullable=True
    )
    al_created_at = Column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
        index=True
    )
    
    # Additional metadata
    al_metadata = Column(
        JSON,
        nullable=True,
        default=dict
    )
    
    # Relationships
    user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="audit_logs",
        lazy="joined"
    )
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_logs_user_id', 'al_user_id'),
        Index('idx_audit_logs_action', 'al_action'),
        Index('idx_audit_logs_entity', 'al_entity_type', 'al_entity_id'),
        Index('idx_audit_logs_created_at', 'al_created_at'),
    )
    
    # Properties
    @property
    def is_authentication_action(self) -> bool:
        """Check if action is authentication related."""
        auth_actions = [
            AuditAction.LOGIN_SUCCESS,
            AuditAction.LOGIN_FAILED,
            AuditAction.LOGOUT,
            AuditAction.TOKEN_REFRESH
        ]
        return self.al_action in auth_actions
    
    @property
    def is_security_action(self) -> bool:
        """Check if action is security related."""
        security_actions = [
            AuditAction.PASSWORD_CHANGED,
            AuditAction.TWO_FACTOR_ENABLED,
            AuditAction.TWO_FACTOR_DISABLED,
            AuditAction.ACCOUNT_LOCKED,
            AuditAction.ACCOUNT_UNLOCKED
        ]
        return self.al_action in security_actions
    
    @property
    def is_failed_action(self) -> bool:
        """Check if action represents a failure."""
        failed_actions = [
            AuditAction.LOGIN_FAILED,
            AuditAction.TWO_FACTOR_FAILED
        ]
        return self.al_action in failed_actions
    
    @property
    def username(self) -> Optional[str]:
        """Get username if user exists."""
        return self.user.u_username if self.user else None
    
    @property
    def email(self) -> Optional[str]:
        """Get email if user exists."""
        return self.user.u_email if self.user else None
    
    # Methods
    def add_metadata(self, key: str, value: Any) -> None:
        """
        Add metadata to audit log.
        
        Args:
            key: Metadata key
            value: Metadata value
        """
        if not self.al_metadata:
            self.al_metadata = {}
        self.al_metadata[key] = value
    
    def get_changes(self) -> Dict[str, Dict[str, Any]]:
        """
        Get formatted changes from old and new values.
        
        Returns:
            Dictionary with changes per field
        """
        changes = {}
        
        if self.al_old_values and self.al_new_values:
            # Find fields that changed
            all_keys = set(self.al_old_values.keys()) | set(self.al_new_values.keys())
            
            for key in all_keys:
                old_val = self.al_old_values.get(key)
                new_val = self.al_new_values.get(key)
                
                if old_val != new_val:
                    changes[key] = {
                        "old": old_val,
                        "new": new_val
                    }
        
        return changes
    
    def to_dict(self, include_user: bool = True) -> Dict[str, Any]:
        """
        Convert audit log to dictionary.
        
        Args:
            include_user: Include user information
            
        Returns:
            Audit log dictionary
        """
        data = {
            "al_id": str(self.al_id),
            "al_user_id": str(self.al_user_id) if self.al_user_id else None,
            "al_action": self.al_action,
            "al_entity_type": self.al_entity_type,
            "al_entity_id": str(self.al_entity_id) if self.al_entity_id else None,
            "al_old_values": self.al_old_values,
            "al_new_values": self.al_new_values,
            "al_ip_address": self.al_ip_address,
            "al_user_agent": self.al_user_agent,
            "al_created_at": self.al_created_at.isoformat() if self.al_created_at else None,
            "al_metadata": self.al_metadata,
            "changes": self.get_changes()
        }
        
        if include_user and self.user:
            data["user"] = {
                "username": self.username,
                "email": self.email
            }
        
        return data
    
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<AuditLog(id={self.al_id}, action={self.al_action}, "
            f"user_id={self.al_user_id}, created_at={self.al_created_at})>"
        )