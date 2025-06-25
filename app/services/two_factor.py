"""
Two-factor authentication service untuk SecureAuth API.
Menangani TOTP, backup codes, dan metode 2FA lainnya.
"""

from datetime import datetime, timezone
from typing import Optional, List, Tuple, Dict, Any
from uuid import UUID
import pyotp
import qrcode
import io
import base64

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.core.config import settings
from app.core.security import security
from app.core.constants import TwoFactorMethod, AuditAction
from app.core.exceptions import (
    NotFoundError,
    ValidationError,
    InvalidCredentialsException,
    AuthenticationError
)
from app.models.user import User
from app.models.two_factor import TwoFactorAuth
from app.services.audit import AuditService
from app.services.email import EmailService


class TwoFactorService:
    """
    Service class untuk two-factor authentication operations.
    """
    
    def __init__(self, db: AsyncSession):
        """
        Initialize 2FA service.
        
        Args:
            db: Database session
        """
        self.db = db
        self.audit_service = AuditService(db)
        self.email_service = EmailService()
    
    async def setup_2fa(
        self,
        user_id: UUID,
        method: TwoFactorMethod = TwoFactorMethod.TOTP
    ) -> Dict[str, Any]:
        """
        Setup 2FA untuk user (belum enabled).
        
        Args:
            user_id: User ID
            method: 2FA method
            
        Returns:
            Setup information (secret, QR code, backup codes)
            
        Raises:
            NotFoundError: Jika user tidak ditemukan
        """
        # Get user
        result = await self.db.execute(
            select(User).where(User.u_id == user_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise NotFoundError("User not found")
        
        # Check existing 2FA
        existing_2fa = await self._get_user_2fa(user_id)
        if existing_2fa and existing_2fa.tfa_is_enabled:
            raise ValidationError("Two-factor authentication is already enabled")
        
        # Generate secret and backup codes
        secret = pyotp.random_base32()
        backup_codes = security.generate_backup_codes(
            count=settings.TWO_FACTOR_BACKUP_CODES_COUNT
        )
        
        if existing_2fa:
            # Update existing record
            existing_2fa.set_secret_key(secret)
            existing_2fa.set_backup_codes(backup_codes)
            existing_2fa.tfa_method = method
        else:
            # Create new 2FA record
            two_fa = TwoFactorAuth(
                tfa_user_id=user_id,
                tfa_method=method
            )
            two_fa.set_secret_key(secret)
            two_fa.set_backup_codes(backup_codes)
            self.db.add(two_fa)
        
        await self.db.commit()
        
        # Generate QR code untuk TOTP
        qr_code = None
        if method == TwoFactorMethod.TOTP:
            provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user.u_email,
                issuer_name=settings.TWO_FACTOR_ISSUER_NAME
            )
            qr_code = self._generate_qr_code(provisioning_uri)
        
        return {
            "method": method,
            "secret": secret,
            "qr_code": qr_code,
            "backup_codes": backup_codes,
            "manual_entry_key": secret
        }
    
    async def enable_2fa(
        self,
        user_id: UUID,
        verification_code: str,
        method: TwoFactorMethod = TwoFactorMethod.TOTP
    ) -> bool:
        """
        Enable 2FA setelah verifikasi code.
        
        Args:
            user_id: User ID
            verification_code: Code untuk verifikasi setup
            method: 2FA method
            
        Returns:
            True jika berhasil enabled
            
        Raises:
            InvalidCredentialsException: Jika verification code salah
        """
        # Get 2FA record
        two_fa = await self._get_user_2fa(user_id)
        if not two_fa:
            raise NotFoundError("Two-factor authentication not set up")
        
        if two_fa.tfa_is_enabled:
            raise ValidationError("Two-factor authentication is already enabled")
        
        # Verify code
        if method == TwoFactorMethod.TOTP:
            if not self._verify_totp_code(two_fa.decrypted_secret, verification_code):
                raise InvalidCredentialsException("Invalid verification code")
        else:
            raise ValidationError(f"Unsupported 2FA method: {method}")
        
        # Enable 2FA
        two_fa.enable()
        
        # Get user untuk email
        user = await self.db.get(User, user_id)
        
        # Send confirmation email dengan backup codes
        await self.email_service.send_2fa_enabled_email(
            email=user.u_email,
            username=user.u_username,
            backup_codes=two_fa.decrypted_backup_codes
        )
        
        # Audit log
        await self.audit_service.log_action(
            action=AuditAction.TWO_FACTOR_ENABLED,
            user_id=user_id,
            entity_type="USER",
            entity_id=user_id,
            metadata={"method": method}
        )
        
        await self.db.commit()
        return True
    
    async def disable_2fa(
        self,
        user_id: UUID,
        password: str
    ) -> bool:
        """
        Disable 2FA dengan password verification.
        
        Args:
            user_id: User ID
            password: User password untuk konfirmasi
            
        Returns:
            True jika berhasil disabled
            
        Raises:
            InvalidCredentialsException: Jika password salah
        """
        # Get user and verify password
        user = await self.db.get(User, user_id)
        if not user:
            raise NotFoundError("User not found")
        
        if not user.verify_password(password):
            raise InvalidCredentialsException("Invalid password")
        
        # Get 2FA record
        two_fa = await self._get_user_2fa(user_id)
        if not two_fa or not two_fa.tfa_is_enabled:
            raise ValidationError("Two-factor authentication is not enabled")
        
        # Disable 2FA
        two_fa.disable()
        
        # Audit log
        await self.audit_service.log_action(
            action=AuditAction.TWO_FACTOR_DISABLED,
            user_id=user_id,
            entity_type="USER",
            entity_id=user_id
        )
        
        await self.db.commit()
        return True
    
    async def verify_2fa_code(
        self,
        session_id: str,
        code: str,
        method: TwoFactorMethod = TwoFactorMethod.TOTP
    ) -> bool:
        """
        Verify 2FA code untuk login.
        
        Args:
            session_id: Temporary session ID dari login
            code: 2FA code
            method: Method yang digunakan
            
        Returns:
            True jika code valid
        """
        # Get user dari temporary session
        # Implementasi akan menggunakan Redis untuk temporary storage
        # Untuk sementara, kita asumsikan session_id maps ke user_id
        
        # TODO: Implement proper session retrieval from Redis
        # user_id = await self._get_user_from_session(session_id)
        
        # Placeholder implementation
        return False
    
    async def verify_user_2fa_code(
        self,
        user_id: UUID,
        code: str,
        method: TwoFactorMethod = TwoFactorMethod.TOTP
    ) -> bool:
        """
        Verify 2FA code untuk user yang sudah diketahui.
        
        Args:
            user_id: User ID
            code: 2FA code
            method: Method yang digunakan
            
        Returns:
            True jika code valid
        """
        # Get 2FA record
        two_fa = await self._get_user_2fa(user_id)
        if not two_fa or not two_fa.tfa_is_enabled:
            raise ValidationError("Two-factor authentication is not enabled")
        
        is_valid = False
        
        if method == TwoFactorMethod.TOTP:
            # Verify TOTP code
            is_valid = self._verify_totp_code(two_fa.decrypted_secret, code)
        elif method == TwoFactorMethod.BACKUP_CODE:
            # Verify backup code
            is_valid = two_fa.use_backup_code(code)
            if is_valid:
                await self.db.commit()
        else:
            raise ValidationError(f"Unsupported 2FA method: {method}")
        
        # Update tracking
        if is_valid:
            two_fa.update_last_used()
            
            # Audit successful 2FA
            await self.audit_service.log_action(
                action=AuditAction.TWO_FACTOR_VERIFIED,
                user_id=user_id,
                metadata={"method": method}
            )
        else:
            # Track failed attempt
            failed_count = two_fa.increment_failed_attempts()
            
            # Audit failed 2FA
            await self.audit_service.log_action(
                action=AuditAction.TWO_FACTOR_FAILED,
                user_id=user_id,
                metadata={
                    "method": method,
                    "failed_attempts": failed_count
                }
            )
        
        await self.db.commit()
        return is_valid
    
    async def regenerate_backup_codes(
        self,
        user_id: UUID,
        password: str
    ) -> List[str]:
        """
        Regenerate backup codes dengan password verification.
        
        Args:
            user_id: User ID
            password: User password untuk konfirmasi
            
        Returns:
            New backup codes
            
        Raises:
            InvalidCredentialsException: Jika password salah
        """
        # Get user and verify password
        user = await self.db.get(User, user_id)
        if not user:
            raise NotFoundError("User not found")
        
        if not user.verify_password(password):
            raise InvalidCredentialsException("Invalid password")
        
        # Get 2FA record
        two_fa = await self._get_user_2fa(user_id)
        if not two_fa or not two_fa.tfa_is_enabled:
            raise ValidationError("Two-factor authentication is not enabled")
        
        # Generate new backup codes
        new_codes = two_fa.regenerate_backup_codes(
            count=settings.TWO_FACTOR_BACKUP_CODES_COUNT
        )
        
        await self.db.commit()
        
        # Send email dengan new codes
        await self.email_service.send_2fa_enabled_email(
            email=user.u_email,
            username=user.u_username,
            backup_codes=new_codes
        )
        
        return new_codes
    
    async def get_2fa_status(self, user_id: UUID) -> Dict[str, Any]:
        """
        Get 2FA status untuk user.
        
        Args:
            user_id: User ID
            
        Returns:
            2FA status information
        """
        two_fa = await self._get_user_2fa(user_id)
        
        if not two_fa:
            return {
                "enabled": False,
                "method": None,
                "backup_codes_remaining": 0
            }
        
        return {
            "enabled": two_fa.tfa_is_enabled,
            "method": two_fa.tfa_method if two_fa.tfa_is_enabled else None,
            "backup_codes_remaining": len(two_fa.decrypted_backup_codes),
            "last_used": two_fa.tfa_last_used_at,
            "failed_attempts": two_fa.tfa_failed_attempts
        }
    
    async def _get_user_2fa(self, user_id: UUID) -> Optional[TwoFactorAuth]:
        """
        Get 2FA record untuk user.
        
        Args:
            user_id: User ID
            
        Returns:
            TwoFactorAuth object atau None
        """
        result = await self.db.execute(
            select(TwoFactorAuth)
            .where(TwoFactorAuth.tfa_user_id == user_id)
        )
        return result.scalar_one_or_none()
    
    def _verify_totp_code(self, secret: str, code: str) -> bool:
        """
        Verify TOTP code.
        
        Args:
            secret: TOTP secret
            code: Code to verify
            
        Returns:
            True jika valid
        """
        if not secret or not code:
            return False
        
        # Remove spaces and ensure 6 digits
        code = code.replace(" ", "").strip()
        if not code.isdigit() or len(code) != 6:
            return False
        
        totp = pyotp.TOTP(secret)
        # Allow 1 window for clock skew
        return totp.verify(code, valid_window=1)
    
    def _generate_qr_code(self, data: str) -> str:
        """
        Generate QR code as base64 data URI.
        
        Args:
            data: Data to encode in QR
            
        Returns:
            Base64 encoded QR code image
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"