"""
Device service untuk SecureAuth API.
Menangani device tracking dan trust management.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from uuid import UUID
import hashlib
import json
import secrets


from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.constants import DeviceType, Platform, AuditAction
from app.core.exceptions import (
    DeviceLimitExceededException,
    NotFoundError,
    ValidationError
)
from app.models.device import UserDevice
from app.models.user import User
from app.services.audit import AuditService


class DeviceService:
    """
    Service class untuk device management operations.
    Menangani device fingerprinting, tracking, dan trust.
    """
    
    def __init__(self, db: AsyncSession):
        """
        Initialize device service.
        
        Args:
            db: Database session
        """
        self.db = db
        self.audit_service = AuditService(db)
    
    async def track_device(
        self,
        user_id: UUID,
        device_info: Dict[str, Any],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        trust_device: bool = False
    ) -> UserDevice:
        """
        Track device yang digunakan untuk login.
        
        Args:
            user_id: User ID
            device_info: Device information dari client
            ip_address: Client IP
            user_agent: User agent string
            trust_device: Whether to trust device immediately
            
        Returns:
            UserDevice object
            
        Raises:
            DeviceLimitExceededException: Jika device limit exceeded
        """
        # Generate device ID/fingerprint
        device_id = device_info.get("device_id") or self._generate_device_id(
            user_agent=user_agent,
            ip_address=ip_address,
            metadata=device_info
        )
        
        # Check existing device
        existing_device = await self.get_user_device(user_id, device_id)
        
        if existing_device:
            # Update existing device
            existing_device.update_last_used()
            
            # Update device info if changed
            if device_info.get("device_name"):
                existing_device.ud_device_name = device_info["device_name"]
            if device_info.get("device_type"):
                existing_device.ud_device_type = device_info["device_type"]
            if device_info.get("platform"):
                existing_device.ud_platform = device_info["platform"]
            if device_info.get("browser"):
                existing_device.ud_browser = device_info["browser"]
            
            # Reactivate if was inactive
            if not existing_device.ud_is_active:
                existing_device.reactivate()
            
            await self.db.commit()
            return existing_device
        
        # Check device limit
        device_count = await self.get_user_device_count(user_id)
        if device_count >= settings.MAX_DEVICES_PER_USER:
            raise DeviceLimitExceededException(
                f"Maximum {settings.MAX_DEVICES_PER_USER} devices allowed",
                max_devices=settings.MAX_DEVICES_PER_USER
            )
        
        # Create new device
        new_device = UserDevice(
            ud_user_id=user_id,
            ud_device_id=device_id,
            ud_device_name=device_info.get("device_name"),
            ud_device_type=device_info.get("device_type"),
            ud_platform=device_info.get("platform"),
            ud_browser=device_info.get("browser"),
            ud_is_trusted=trust_device,
            ud_last_used_at=datetime.now(timezone.utc),
            ud_metadata=json.dumps(device_info.get("metadata", {}))
        )
        
        self.db.add(new_device)
        
        # Audit device addition
        await self.audit_service.log_action(
            action=AuditAction.DEVICE_ADDED,
            user_id=user_id,
            entity_type="DEVICE",
            entity_id=new_device.ud_id,
            ip_address=ip_address,
            user_agent=user_agent,
            new_values={
                "device_id": device_id,
                "device_name": new_device.display_name,
                "trusted": trust_device
            }
        )
        
        await self.db.commit()
        return new_device
    
    async def get_user_device(
        self,
        user_id: UUID,
        device_id: str
    ) -> Optional[UserDevice]:
        """
        Get specific device untuk user.
        
        Args:
            user_id: User ID
            device_id: Device ID/fingerprint
            
        Returns:
            UserDevice atau None
        """
        result = await self.db.execute(
            select(UserDevice)
            .where(
                and_(
                    UserDevice.ud_user_id == user_id,
                    UserDevice.ud_device_id == device_id
                )
            )
        )
        return result.scalar_one_or_none()
    
    async def get_user_devices(
        self,
        user_id: UUID,
        active_only: bool = True
    ) -> List[UserDevice]:
        """
        Get semua devices untuk user.
        
        Args:
            user_id: User ID
            active_only: Whether to return only active devices
            
        Returns:
            List of UserDevice objects
        """
        query = select(UserDevice).where(UserDevice.ud_user_id == user_id)
        
        if active_only:
            query = query.where(UserDevice.ud_is_active == True)
        
        query = query.order_by(UserDevice.ud_last_used_at.desc().nullslast())
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_user_device_count(
        self,
        user_id: UUID,
        active_only: bool = True
    ) -> int:
        """
        Get count of user devices.
        
        Args:
            user_id: User ID
            active_only: Whether to count only active devices
            
        Returns:
            Device count
        """
        query = select(func.count(UserDevice.ud_id)).where(
            UserDevice.ud_user_id == user_id
        )
        
        if active_only:
            query = query.where(UserDevice.ud_is_active == True)
        
        result = await self.db.execute(query)
        return result.scalar() or 0
    
    async def trust_device(
        self,
        user_id: UUID,
        device_id: str,
        trusted_by: Optional[UUID] = None
    ) -> bool:
        """
        Mark device as trusted.
        
        Args:
            user_id: User ID
            device_id: Device ID to trust
            trusted_by: Admin user ID jika trusted oleh admin
            
        Returns:
            True jika berhasil
            
        Raises:
            NotFoundError: Jika device tidak ditemukan
        """
        device = await self.get_user_device(user_id, device_id)
        if not device:
            raise NotFoundError("Device not found")
        
        if device.ud_is_trusted:
            return True  # Already trusted
        
        device.trust_device()
        
        # Audit trust action
        await self.audit_service.log_action(
            action=AuditAction.DEVICE_TRUSTED,
            user_id=trusted_by or user_id,
            entity_type="DEVICE",
            entity_id=device.ud_id,
            metadata={
                "device_name": device.display_name,
                "trusted_by_admin": bool(trusted_by)
            }
        )
        
        await self.db.commit()
        return True
    
    async def untrust_device(
        self,
        user_id: UUID,
        device_id: str
    ) -> bool:
        """
        Remove trust from device.
        
        Args:
            user_id: User ID
            device_id: Device ID to untrust
            
        Returns:
            True jika berhasil
        """
        device = await self.get_user_device(user_id, device_id)
        if not device:
            raise NotFoundError("Device not found")
        
        device.untrust_device()
        await self.db.commit()
        
        return True
    
    async def remove_device(
        self,
        user_id: UUID,
        device_id: str,
        removed_by: Optional[UUID] = None
    ) -> bool:
        """
        Remove/deactivate device.
        
        Args:
            user_id: User ID
            device_id: Device ID to remove
            removed_by: Admin user ID jika removed oleh admin
            
        Returns:
            True jika berhasil
        """
        device = await self.get_user_device(user_id, device_id)
        if not device:
            raise NotFoundError("Device not found")
        
        device.deactivate()
        
        # Audit device removal
        await self.audit_service.log_action(
            action=AuditAction.DEVICE_REMOVED,
            user_id=removed_by or user_id,
            entity_type="DEVICE",
            entity_id=device.ud_id,
            metadata={
                "device_name": device.display_name,
                "removed_by_admin": bool(removed_by)
            }
        )
        
        await self.db.commit()
        return True
    
    async def is_device_trusted(
        self,
        user_id: UUID,
        device_id: str
    ) -> bool:
        """
        Check if device is trusted.
        
        Args:
            user_id: User ID
            device_id: Device ID
            
        Returns:
            True jika device trusted dan masih valid
        """
        device = await self.get_user_device(user_id, device_id)
        
        if not device or not device.ud_is_active or not device.ud_is_trusted:
            return False
        
        # Check if trust has expired
        if device.ud_last_used_at:
            days_since_use = (datetime.now(timezone.utc) - device.ud_last_used_at).days
            if days_since_use > settings.DEVICE_TRUST_DAYS:
                # Untrust device karena expired
                device.untrust_device()
                await self.db.commit()
                return False
        
        return True
    
    async def cleanup_inactive_devices(
        self,
        inactive_days: int = 90
    ) -> int:
        """
        Cleanup devices yang tidak aktif dalam period tertentu.
        
        Args:
            inactive_days: Days of inactivity before cleanup
            
        Returns:
            Number of devices cleaned up
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=inactive_days)
        
        # Get inactive devices
        result = await self.db.execute(
            select(UserDevice)
            .where(
                and_(
                    UserDevice.ud_is_active == True,
                    or_(
                        UserDevice.ud_last_used_at < cutoff_date,
                        UserDevice.ud_last_used_at.is_(None)
                    )
                )
            )
        )
        devices = result.scalars().all()
        
        cleaned_count = 0
        for device in devices:
            device.deactivate()
            cleaned_count += 1
        
        if cleaned_count > 0:
            await self.db.commit()
        
        return cleaned_count
    
    def _generate_device_id(
        self,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate device ID/fingerprint dari available information.
        
        Args:
            user_agent: User agent string
            ip_address: IP address
            metadata: Additional device metadata
            
        Returns:
            Generated device ID
        """
        # Combine available information untuk fingerprint
        parts = []
        
        if user_agent:
            parts.append(user_agent)
        
        if metadata:
            # Use stable device properties
            if metadata.get("screen_resolution"):
                parts.append(str(metadata["screen_resolution"]))
            if metadata.get("timezone"):
                parts.append(str(metadata["timezone"]))
            if metadata.get("language"):
                parts.append(metadata["language"])
            if metadata.get("platform"):
                parts.append(metadata["platform"])
        
        # Fallback to random ID if no stable properties
        if not parts:
            return f"device_{UUID(int=secrets.randbits(128))}"
        
        # Generate hash from parts
        fingerprint_data = "|".join(parts)
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]
    
    async def get_device_statistics(
        self,
        user_id: UUID
    ) -> Dict[str, Any]:
        """
        Get device statistics untuk user.
        
        Args:
            user_id: User ID
            
        Returns:
            Device statistics
        """
        devices = await self.get_user_devices(user_id, active_only=False)
        
        active_devices = [d for d in devices if d.ud_is_active]
        trusted_devices = [d for d in active_devices if d.ud_is_trusted]
        
        # Group by type
        device_types = {}
        for device in active_devices:
            device_type = device.ud_device_type or "Unknown"
            device_types[device_type] = device_types.get(device_type, 0) + 1
        
        # Group by platform
        platforms = {}
        for device in active_devices:
            platform = device.ud_platform or "Unknown"
            platforms[platform] = platforms.get(platform, 0) + 1
        
        return {
            "total_devices": len(devices),
            "active_devices": len(active_devices),
            "trusted_devices": len(trusted_devices),
            "device_types": device_types,
            "platforms": platforms,
            "recently_used": len([d for d in active_devices if d.is_recently_used])
        }