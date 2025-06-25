"""
User service untuk SecureAuth API.
Menangani business logic untuk user management.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.security import security
from app.core.constants import AuditAction, TokenType, LogoutReason 
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    ValidationError,
    WeakPasswordException,
    PasswordReuseException,
    InvalidCredentialsException
)
from app.models.user import User
from app.models.password_history import PasswordHistory
from app.models.session import UserSession
from app.models.token import UserToken
from app.services.audit import AuditService
from app.services.token import TokenService
from app.models.login_attempt import LoginAttempt


class UserService:
    """
    Service class untuk user operations.
    Menangani CRUD operations dan business logic untuk users.
    """
    
    def __init__(self, db: AsyncSession):
        """
        Initialize user service.
        
        Args:
            db: Database session
        """
        self.db = db
        self.audit_service = AuditService(db)
        self.token_service = TokenService(db)
    
    async def create_user(
        self,
        email: str,
        username: str,
        password: str,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> User:
        """
        Create new user dengan validasi lengkap.
        
        Args:
            email: User email
            username: Username
            password: Plain text password
            metadata: Additional user metadata
            ip_address: Registration IP
            user_agent: Registration user agent
            
        Returns:
            Created user object
            
        Raises:
            ConflictError: Jika email/username sudah ada
            WeakPasswordException: Jika password tidak memenuhi requirements
        """
        # Normalize input
        email = email.lower().strip()
        username = username.strip()
        
        # Validate password strength
        is_valid, errors = security.validate_password_strength(password)
        if not is_valid:
            raise WeakPasswordException(
                message="Password does not meet requirements",
                errors=errors
            )
        
        # Check if email already exists
        existing_email = await self.get_user_by_email(email)
        if existing_email:
            raise ConflictError("Email already registered")
        
        # Check if username already exists
        existing_username = await self.get_user_by_username(username)
        if existing_username:
            raise ConflictError("Username already taken")
        
        # Create user
        user = User(
            u_email=email,
            u_username=username,
            u_metadata=metadata or {},
            u_ip_address=ip_address,
            u_user_agent=user_agent
        )
        
        # Set password (akan di-hash)
        user.set_password(password)
        
        # Add to database
        self.db.add(user)
        
        try:
            await self.db.flush()
            
            # Add password to history
            password_history = PasswordHistory.create_from_password(
                user_id=user.u_id,
                password=password
            )
            self.db.add(password_history)
            
            # Audit user creation
            await self.audit_service.log_action(
                action=AuditAction.ACCOUNT_CREATED,
                user_id=user.u_id,
                entity_type="USER",
                entity_id=user.u_id,
                ip_address=ip_address,
                user_agent=user_agent,
                new_values={
                    "email": email,
                    "username": username
                }
            )
            
            await self.db.commit()
            
            return user
            
        except IntegrityError as e:
            await self.db.rollback()
            # Handle race condition
            if "u_email" in str(e):
                raise ConflictError("Email already registered")
            elif "u_username" in str(e):
                raise ConflictError("Username already taken")
            raise
    
    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        """
        Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User object atau None
        """
        result = await self.db.execute(
            select(User).where(User.u_id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email.
        
        Args:
            email: User email
            
        Returns:
            User object atau None
        """
        email = email.lower().strip()
        result = await self.db.execute(
            select(User).where(User.u_email == email)
        )
        return result.scalar_one_or_none()
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username.
        
        Args:
            username: Username
            
        Returns:
            User object atau None
        """
        username = username.strip()
        result = await self.db.execute(
            select(User).where(User.u_username == username)
        )
        return result.scalar_one_or_none()
    
    async def update_user(
        self,
        user_id: UUID,
        update_data: Dict[str, Any],
        updated_by: Optional[UUID] = None
    ) -> User:
        """
        Update user data.
        
        Args:
            user_id: User ID to update
            update_data: Data to update
            updated_by: User ID yang melakukan update
            
        Returns:
            Updated user object
            
        Raises:
            NotFoundError: Jika user tidak ditemukan
            ConflictError: Jika username sudah digunakan
        """
        # Get user
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Track old values for audit
        old_values = {}
        
        # Update username if provided
        if "username" in update_data:
            new_username = update_data["username"].strip()
            if new_username != user.u_username:
                # Check if username already taken
                existing = await self.get_user_by_username(new_username)
                if existing and existing.u_id != user_id:
                    raise ConflictError("Username already taken")
                
                old_values["username"] = user.u_username
                user.u_username = new_username
        
        # Update metadata if provided
        if "metadata" in update_data:
            old_values["metadata"] = user.u_metadata.copy() if user.u_metadata else {}
            if user.u_metadata:
                user.u_metadata.update(update_data["metadata"])
            else:
                user.u_metadata = update_data["metadata"]
        
        # Update timestamp
        user.u_updated_at = datetime.now(timezone.utc)
        
        # Audit changes
        if old_values:
            await self.audit_service.log_action(
                action=AuditAction.PROFILE_UPDATED,
                user_id=updated_by or user_id,
                entity_type="USER",
                entity_id=user_id,
                old_values=old_values,
                new_values=update_data
            )
        
        await self.db.commit()
        await self.db.refresh(user)
        
        return user
    
    async def change_password(
        self,
        user_id: UUID,
        current_password: str,
        new_password: str
    ) -> bool:
        """
        Change user password dengan validasi.
        
        Args:
            user_id: User ID
            current_password: Current password
            new_password: New password
            
        Returns:
            True jika berhasil
            
        Raises:
            NotFoundError: Jika user tidak ditemukan
            InvalidCredentialsException: Jika current password salah
            WeakPasswordException: Jika new password lemah
            PasswordReuseException: Jika password sudah pernah digunakan
        """
        # Get user
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Verify current password
        if not user.verify_password(current_password):
            raise InvalidCredentialsException("Current password is incorrect")
        
        # Validate new password strength
        is_valid, errors = security.validate_password_strength(new_password)
        if not is_valid:
            raise WeakPasswordException(
                message="New password does not meet requirements",
                errors=errors
            )
        
        # Check password history
        if settings.PASSWORD_HISTORY_COUNT > 0:
            # Get password history
            result = await self.db.execute(
                select(PasswordHistory)
                .where(PasswordHistory.ph_user_id == user_id)
                .order_by(PasswordHistory.ph_created_at.desc())
                .limit(settings.PASSWORD_HISTORY_COUNT)
            )
            password_history = result.scalars().all()
            
            # Check if password was used before
            if PasswordHistory.check_password_reuse(user_id, new_password, password_history):
                raise PasswordReuseException(
                    f"Password has been used in the last {settings.PASSWORD_HISTORY_COUNT} passwords"
                )
        
        # Set new password
        user.set_password(new_password)
        user.u_updated_at = datetime.now(timezone.utc)
        
        # Add to password history
        new_history = PasswordHistory.create_from_password(user_id, new_password)
        self.db.add(new_history)
        
        # Audit password change
        await self.audit_service.log_action(
            action=AuditAction.PASSWORD_CHANGED,
            user_id=user_id,
            entity_type="USER",
            entity_id=user_id
        )
        
        await self.db.commit()
        
        return True
    
    async def reset_password(
        self,
        user_id: UUID,
        new_password: str,
        reset_by: Optional[UUID] = None
    ) -> bool:
        """
        Reset user password (tanpa perlu current password).
        
        Args:
            user_id: User ID
            new_password: New password
            reset_by: Admin user ID jika reset oleh admin
            
        Returns:
            True jika berhasil
            
        Raises:
            NotFoundError: Jika user tidak ditemukan
            WeakPasswordException: Jika password lemah
        """
        # Get user
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Validate password strength
        is_valid, errors = security.validate_password_strength(new_password)
        if not is_valid:
            raise WeakPasswordException(
                message="Password does not meet requirements",
                errors=errors
            )
        
        # Set new password
        user.set_password(new_password)
        user.u_updated_at = datetime.now(timezone.utc)
        
        # Reset failed login attempts
        user.u_failed_login_attempts = 0
        
        # Unlock account if locked
        if user.u_is_locked:
            user.unlock_account()
        
        # Add to password history
        new_history = PasswordHistory.create_from_password(user_id, new_password)
        self.db.add(new_history)
        
        # Audit password reset
        await self.audit_service.log_action(
            action=AuditAction.PASSWORD_RESET_COMPLETED,
            user_id=reset_by or user_id,
            entity_type="USER",
            entity_id=user_id,
            metadata={"reset_by_admin": bool(reset_by)}
        )
        
        await self.db.commit()
        
        return True
    
    async def verify_email(self, user_id: UUID) -> bool:
        """
        Mark user email as verified.
        
        Args:
            user_id: User ID
            
        Returns:
            True jika berhasil
            
        Raises:
            NotFoundError: Jika user tidak ditemukan
        """
        # Get user
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Check if already verified
        if user.u_is_verified:
            return True
        
        # Verify email
        user.verify_email()
        
        # Audit email verification
        await self.audit_service.log_action(
            action=AuditAction.ACCOUNT_VERIFIED,
            user_id=user_id,
            entity_type="USER",
            entity_id=user_id
        )
        
        await self.db.commit()
        
        return True
    
    async def lock_user_account(
        self,
        user_id: UUID,
        locked_until: datetime,
        reason: str,
        locked_by: Optional[UUID] = None
    ) -> bool:
        """
        Lock user account.
        
        Args:
            user_id: User ID to lock
            locked_until: Lock expiration
            reason: Lock reason
            locked_by: Admin user ID jika locked oleh admin
            
        Returns:
            True jika berhasil
        """
        # Get user
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Lock account
        user.lock_account(locked_until)
        
        # Terminate all sessions
        from app.services.auth import AuthService
        auth_service = AuthService(self.db)
        await auth_service.terminate_all_sessions(
            user_id=user_id,
            reason=LogoutReason.ACCOUNT_LOCKED
        )
        
        # Audit account lock
        await self.audit_service.log_action(
            action=AuditAction.ACCOUNT_LOCKED,
            user_id=locked_by or user_id,
            entity_type="USER",
            entity_id=user_id,
            metadata={
                "reason": reason,
                "locked_until": locked_until.isoformat(),
                "locked_by_admin": bool(locked_by)
            }
        )
        
        await self.db.commit()
        
        return True
    
    async def unlock_user_account(
        self,
        user_id: UUID,
        unlocked_by: Optional[UUID] = None
    ) -> bool:
        """
        Unlock user account.
        
        Args:
            user_id: User ID to unlock
            unlocked_by: Admin user ID jika unlocked oleh admin
            
        Returns:
            True jika berhasil
        """
        # Get user
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Unlock account
        user.unlock_account()
        
        # Audit account unlock
        await self.audit_service.log_action(
            action=AuditAction.ACCOUNT_UNLOCKED,
            user_id=unlocked_by or user_id,
            entity_type="USER",
            entity_id=user_id,
            metadata={"unlocked_by_admin": bool(unlocked_by)}
        )
        
        await self.db.commit()
        
        return True
    
    async def delete_user(
        self,
        user_id: UUID,
        deleted_by: Optional[UUID] = None,
        soft_delete: bool = True
    ) -> bool:
        """
        Delete user account.
        
        Args:
            user_id: User ID to delete
            deleted_by: Admin user ID jika deleted oleh admin
            soft_delete: Jika True, hanya deactivate. Jika False, hard delete
            
        Returns:
            True jika berhasil
        """
        # Get user
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        if soft_delete:
            # Soft delete - deactivate account
            user.u_is_active = False
            user.u_updated_at = datetime.now(timezone.utc)
            
            # Terminate all sessions
            from app.services.auth import AuthService
            auth_service = AuthService(self.db)
            await auth_service.terminate_all_sessions(
                user_id=user_id,
                reason=LogoutReason.ACCOUNT_DELETED
            )
            
            # Audit soft delete
            await self.audit_service.log_action(
                action=AuditAction.ACCOUNT_DELETED,
                user_id=deleted_by or user_id,
                entity_type="USER",
                entity_id=user_id,
                metadata={
                    "soft_delete": True,
                    "deleted_by_admin": bool(deleted_by)
                }
            )
            
        else:
            # Hard delete - remove from database
            # Audit first before deletion
            await self.audit_service.log_action(
                action=AuditAction.ACCOUNT_DELETED,
                user_id=deleted_by or user_id,
                entity_type="USER",
                entity_id=user_id,
                metadata={
                    "soft_delete": False,
                    "deleted_by_admin": bool(deleted_by),
                    "email": user.u_email,
                    "username": user.u_username
                }
            )
            
            await self.db.delete(user)
        
        await self.db.commit()
        
        return True
    
    async def get_users(
        self,
        page: int = 1,
        per_page: int = 20,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_verified: Optional[bool] = None,
        order_by: str = "created_at",
        order_desc: bool = True
    ) -> Tuple[List[User], int]:
        """
        Get paginated list of users dengan filtering.
        
        Args:
            page: Page number
            per_page: Items per page
            search: Search term untuk email/username
            is_active: Filter by active status
            is_verified: Filter by verified status
            order_by: Field to order by
            order_desc: Order descending
            
        Returns:
            Tuple of (users, total_count)
        """
        # Build base query
        query = select(User)
        count_query = select(func.count(User.u_id))
        
        # Apply filters
        if search:
            search_filter = or_(
                User.u_email.ilike(f"%{search}%"),
                User.u_username.ilike(f"%{search}%")
            )
            query = query.where(search_filter)
            count_query = count_query.where(search_filter)
        
        if is_active is not None:
            query = query.where(User.u_is_active == is_active)
            count_query = count_query.where(User.u_is_active == is_active)
        
        if is_verified is not None:
            query = query.where(User.u_is_verified == is_verified)
            count_query = count_query.where(User.u_is_verified == is_verified)
        
        # Get total count
        total_result = await self.db.execute(count_query)
        total_count = total_result.scalar()
        
        # Apply ordering
        order_field = getattr(User, f"u_{order_by}", User.u_created_at)
        if order_desc:
            query = query.order_by(order_field.desc())
        else:
            query = query.order_by(order_field)
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.limit(per_page).offset(offset)
        
        # Execute query
        result = await self.db.execute(query)
        users = result.scalars().all()
        
        return users, total_count
    
    async def get_user_statistics(self, user_id: UUID) -> Dict[str, Any]:
        """
        Get user statistics dan activity summary.
        
        Args:
            user_id: User ID
            
        Returns:
            Dictionary dengan statistics
        """
        # Get user
        user = await self.get_user_by_id(user_id)
        if not user:
            raise NotFoundError("User not found")
        
        # Count active sessions
        session_count_result = await self.db.execute(
            select(func.count(UserSession.us_id))
            .where(
                and_(
                    UserSession.us_user_id == user_id,
                    UserSession.us_is_active == True
                )
            )
        )
        active_sessions = session_count_result.scalar() or 0
        
        # Count login attempts
        login_count_result = await self.db.execute(
            select(func.count(LoginAttempt.la_id))
            .where(LoginAttempt.la_user_id == user_id)
        )
        total_logins = login_count_result.scalar() or 0
        
        # Count failed login attempts
        failed_count_result = await self.db.execute(
            select(func.count(LoginAttempt.la_id))
            .where(
                and_(
                    LoginAttempt.la_user_id == user_id,
                    LoginAttempt.la_success == False
                )
            )
        )
        failed_logins = failed_count_result.scalar() or 0
        
        # Get last password change
        password_history_result = await self.db.execute(
            select(PasswordHistory.ph_created_at)
            .where(PasswordHistory.ph_user_id == user_id)
            .order_by(PasswordHistory.ph_created_at.desc())
            .limit(1)
        )
        last_password_change = password_history_result.scalar()
        
        return {
            "user_id": user_id,
            "active_sessions": active_sessions,
            "total_logins": total_logins,
            "failed_logins": failed_logins,
            "last_password_change": last_password_change,
            "account_age_days": (datetime.now(timezone.utc) - user.u_created_at).days if user.u_created_at else 0,
            "is_2fa_enabled": user.has_2fa_enabled
        }