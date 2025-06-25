"""
Two-factor authentication model untuk SecureAuth API.
Mengelola konfigurasi 2FA untuk setiap user.
"""

from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, TYPE_CHECKING
from uuid import UUID
import json

from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer, ForeignKey,
    Text, Index, text, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID
from sqlalchemy.orm import relationship, Mapped

from app.db.base import BaseModel
from app.core.constants import TwoFactorMethod
from app.core.security import security

if TYPE_CHECKING:
    from app.models.user import User


class TwoFactorAuth(BaseModel):
    """
    Two-factor authentication configuration model.
    
    Menyimpan konfigurasi 2FA untuk user termasuk secret key,
    backup codes, dan tracking penggunaan.
    
    Attributes:
        tfa_id: 2FA configuration ID (UUID)
        tfa_user_id: User ID yang memiliki 2FA config
        tfa_secret_key: Encrypted TOTP secret key
        tfa_backup_codes: Encrypted/hashed backup codes
        tfa_is_enabled: Whether 2FA is enabled
        tfa_method: 2FA method (TOTP, SMS, etc)
        tfa_enabled_at: When 2FA was enabled
        tfa_last_used_at: Last time 2FA was used
        tfa_failed_attempts: Number of failed 2FA attempts
    """
    
    __tablename__ = "two_factor_auth"
    
    # Primary key
    tfa_id = Column(
        PostgresUUID(as_uuid=True),
        primary_key=True,
        server_default=text("uuid_generate_v4()"),
        nullable=False,
        index=True
    )
    
    # Foreign key
    tfa_user_id = Column(
        PostgresUUID(as_uuid=True),
        ForeignKey("users.u_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,  # One 2FA config per user
        index=True
    )
    
    # 2FA configuration
    tfa_secret_key = Column(
        Text,  # Encrypted
        nullable=True
    )
    tfa_backup_codes = Column(
        Text,  # Encrypted JSON array
        nullable=True
    )
    tfa_is_enabled = Column(
        Boolean,
        default=False,
        nullable=False,
        index=True
    )
    tfa_method = Column(
        String(50),
        nullable=False,
        default=TwoFactorMethod.TOTP
    )
    
    # Timestamps and tracking
    tfa_enabled_at = Column(
        DateTime(timezone=True),
        nullable=True
    )
    tfa_last_used_at = Column(
        DateTime(timezone=True),
        nullable=True
    )
    tfa_failed_attempts = Column(
        Integer,
        default=0,
        nullable=False
    )
    
    # Additional settings
    tfa_phone_number = Column(
        String(20),  # For SMS method
        nullable=True
    )
    tfa_email = Column(
        String(255),  # For email method
        nullable=True
    )
    
    # Relationships
    user: Mapped["User"] = relationship(
        "User",
        back_populates="two_factor_auth",
        lazy="joined"
    )
    
    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint('tfa_user_id', name='uq_two_factor_auth_user_id'),
        Index('idx_two_factor_auth_is_enabled', 'tfa_is_enabled'),
    )
    
    # Properties
    @property
    def is_totp(self) -> bool:
        """Check if using TOTP method."""
        return self.tfa_method == TwoFactorMethod.TOTP
    
    @property
    def is_sms(self) -> bool:
        """Check if using SMS method."""
        return self.tfa_method == TwoFactorMethod.SMS
    
    @property
    def is_email(self) -> bool:
        """Check if using email method."""
        return self.tfa_method == TwoFactorMethod.EMAIL
    
    @property
    def has_backup_codes(self) -> bool:
        """Check if user has backup codes."""
        return bool(self.tfa_backup_codes)
    
    @property
    def decrypted_secret(self) -> Optional[str]:
        """Get decrypted secret key."""
        if self.tfa_secret_key:
            try:
                return security.decrypt(self.tfa_secret_key)
            except Exception:
                return None
        return None
    
    @property
    def decrypted_backup_codes(self) -> List[str]:
        """Get decrypted backup codes."""
        if self.tfa_backup_codes:
            try:
                decrypted = security.decrypt(self.tfa_backup_codes)
                return json.loads(decrypted)
            except Exception:
                return []
        return []
    
    # Methods
    def set_secret_key(self, secret_key: str) -> None:
        """
        Set encrypted secret key.
        
        Args:
            secret_key: Plain text secret key
        """
        self.tfa_secret_key = security.encrypt(secret_key)
    
    def set_backup_codes(self, backup_codes: List[str]) -> None:
        """
        Set encrypted backup codes.
        
        Args:
            backup_codes: List of backup codes
        """
        self.tfa_backup_codes = security.encrypt(json.dumps(backup_codes))
    
    def enable(self) -> None:
        """Enable 2FA."""
        self.tfa_is_enabled = True
        self.tfa_enabled_at = datetime.now(timezone.utc)
        self.tfa_failed_attempts = 0
    
    def disable(self) -> None:
        """Disable 2FA."""
        self.tfa_is_enabled = False
        self.tfa_secret_key = None
        self.tfa_backup_codes = None
        self.tfa_failed_attempts = 0
    
    def update_last_used(self) -> None:
        """Update last used timestamp."""
        self.tfa_last_used_at = datetime.now(timezone.utc)
        self.tfa_failed_attempts = 0
    
    def increment_failed_attempts(self) -> int:
        """
        Increment failed attempts counter.
        
        Returns:
            New failed attempts count
        """
        self.tfa_failed_attempts += 1
        return self.tfa_failed_attempts
    
    def reset_failed_attempts(self) -> None:
        """Reset failed attempts counter."""
        self.tfa_failed_attempts = 0
    
    def use_backup_code(self, code: str) -> bool:
        """
        Use a backup code (removes it from list).
        
        Args:
            code: Backup code to use
            
        Returns:
            True if code was valid and used
        """
        backup_codes = self.decrypted_backup_codes
        
        # Normalize code format (remove dashes)
        normalized_code = code.replace("-", "").upper()
        
        # Check each backup code
        for i, stored_code in enumerate(backup_codes):
            if stored_code.replace("-", "").upper() == normalized_code:
                # Remove used code
                backup_codes.pop(i)
                self.set_backup_codes(backup_codes)
                self.update_last_used()
                return True
        
        return False
    
    def regenerate_backup_codes(self, count: int = 10) -> List[str]:
        """
        Generate new backup codes.
        
        Args:
            count: Number of backup codes to generate
            
        Returns:
            List of new backup codes
        """
        from app.core.security import security
        
        new_codes = security.generate_backup_codes(count)
        self.set_backup_codes(new_codes)
        return new_codes
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Convert 2FA config to dictionary.
        
        Args:
            include_sensitive: Include sensitive data
            
        Returns:
            2FA config dictionary
        """
        data = {
            "tfa_id": str(self.tfa_id),
            "tfa_user_id": str(self.tfa_user_id),
            "tfa_is_enabled": self.tfa_is_enabled,
            "tfa_method": self.tfa_method,
            "tfa_enabled_at": self.tfa_enabled_at.isoformat() if self.tfa_enabled_at else None,
            "tfa_last_used_at": self.tfa_last_used_at.isoformat() if self.tfa_last_used_at else None,
            "has_backup_codes": self.has_backup_codes
        }
        
        if include_sensitive:
            data.update({
                "tfa_failed_attempts": self.tfa_failed_attempts,
                "backup_codes_count": len(self.decrypted_backup_codes)
            })
        
        return data
    
    def __repr__(self) -> str:
        """String representation."""
        return (
            f"<TwoFactorAuth(id={self.tfa_id}, user_id={self.tfa_user_id}, "
            f"enabled={self.tfa_is_enabled}, method={self.tfa_method})>"
        )