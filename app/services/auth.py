"""
Authentication service untuk SecureAuth API.
Menangani business logic untuk authentication, login, logout, dan session management.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Tuple
from uuid import UUID
import secrets

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload 

from app.core.config import settings
from app.core.security import security
from app.core.constants import (
    AuditAction, 
    LogoutReason, 
    LoginFailureReason,
    ResponseMessage
)
from app.core.exceptions import (
    InvalidCredentialsException,
    AccountLockedException,
    EmailNotVerifiedException,
    TwoFactorRequiredException,
    TokenError,
    AuthenticationError
)
from app.models.user import User
from app.models.session import UserSession
from app.models.login_attempt import LoginAttempt
from app.services.audit import AuditService
from app.services.two_factor import TwoFactorService
from app.services.device import DeviceService


class AuthService:
    """
    Service class untuk authentication operations.
    Menangani login, logout, session management, dan refresh tokens.
    """
    
    def __init__(self, db: AsyncSession):
        """
        Initialize authentication service.
        
        Args:
            db: Database session
        """
        self.db = db
        self.audit_service = AuditService(db)
        self.two_factor_service = TwoFactorService(db)
        
    async def authenticate_user(
        self,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Authenticate user dengan email dan password.
        
        Proses:
        1. Cari user berdasarkan email
        2. Verifikasi password
        3. Check account status (locked, verified)
        4. Record login attempt
        5. Handle 2FA jika enabled
        6. Create session dan tokens
        
        Args:
            email: User email
            password: Plain text password
            ip_address: Client IP address
            user_agent: User agent string
            device_info: Device information
            
        Returns:
            Dict dengan access_token, refresh_token, user object, dan flags
            
        Raises:
            InvalidCredentialsException: Jika kredensial tidak valid
            AccountLockedException: Jika akun terkunci
            EmailNotVerifiedException: Jika email belum diverifikasi
            TwoFactorRequiredException: Jika 2FA diperlukan
        """
        # Normalize email
        email = email.lower().strip()
        
        # Get user by email
        result = await self.db.execute(
            select(User).where(User.u_email == email)
        )
        user = result.scalar_one_or_none()
        
        # Track login attempt
        login_attempt = None
        failure_reason = None
        
        try:
            # Check if user exists
            if not user:
                failure_reason = LoginFailureReason.INVALID_CREDENTIALS
                raise InvalidCredentialsException()
            
            # Check if account is locked
            if user.is_locked_now:
                failure_reason = LoginFailureReason.ACCOUNT_LOCKED
                locked_until = user.u_locked_until.isoformat() if user.u_locked_until else None
                raise AccountLockedException(
                    message=ResponseMessage.ACCOUNT_LOCKED,
                    locked_until=locked_until
                )
            
            # Verify password
            if not user.verify_password(password):
                failure_reason = LoginFailureReason.INVALID_CREDENTIALS
                
                # Increment failed attempts
                failed_count = user.increment_failed_login_attempts()
                
                # Lock account if too many failures
                if failed_count >= settings.MAX_LOGIN_ATTEMPTS:
                    lockout_until = datetime.now(timezone.utc) + settings.account_lockout_timedelta
                    user.lock_account(lockout_until)
                    
                    # Audit log
                    await self.audit_service.log_action(
                        action=AuditAction.ACCOUNT_LOCKED,
                        user_id=user.u_id,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        metadata={"reason": "max_failed_attempts"}
                    )
                
                await self.db.commit()
                raise InvalidCredentialsException()
            
            # Check if email is verified
            if settings.REQUIRE_EMAIL_VERIFICATION and not user.u_is_verified:
                failure_reason = LoginFailureReason.ACCOUNT_NOT_VERIFIED
                raise EmailNotVerifiedException()
            
            # Check if account is active
            if not user.u_is_active:
                failure_reason = LoginFailureReason.ACCOUNT_DISABLED
                raise InvalidCredentialsException("Account is disabled")
            
            # Create successful login attempt record
            login_attempt = LoginAttempt.create_successful(
                user_id=user.u_id,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                metadata=device_info
            )
            self.db.add(login_attempt)
            
            # Check if 2FA is required
            if user.has_2fa_enabled:
                # Check if device is trusted
                if device_info and device_info.get("device_id"):
                    device_service = DeviceService(self.db)
                    is_trusted = await device_service.is_device_trusted(
                        user_id=user.u_id,
                        device_id=device_info["device_id"]
                    )
                    
                    if not is_trusted:
                        # Create temporary 2FA session
                        session_id = await self._create_2fa_session(
                            user=user,
                            ip_address=ip_address,
                            user_agent=user_agent
                        )
                        
                        await self.db.commit()
                        
                        # Require 2FA verification
                        raise TwoFactorRequiredException(
                            session_id=session_id
                        )
                else:
                    # No device info, require 2FA
                    session_id = await self._create_2fa_session(
                        user=user,
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                    
                    await self.db.commit()
                    
                    raise TwoFactorRequiredException(
                        session_id=session_id
                    )
            
            # Reset failed login attempts
            user.update_last_login()
            
            # Create session and tokens
            session_data = await self.create_user_session(
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info
            )
            
            # Audit successful login
            await self.audit_service.log_action(
                action=AuditAction.LOGIN_SUCCESS,
                user_id=user.u_id,
                ip_address=ip_address,
                user_agent=user_agent,
                metadata={"session_id": str(session_data["session_id"])}
            )
            
            await self.db.commit()
            
            return {
                "access_token": session_data["access_token"],
                "refresh_token": session_data["refresh_token"],
                "user": user,
                "requires_2fa": False
            }
            
        except Exception as e:
            # Create failed login attempt if not already created
            if not login_attempt and failure_reason:
                login_attempt = LoginAttempt.create_failed(
                    email=email,
                    failure_reason=failure_reason,
                    user_id=user.u_id if user else None,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    metadata=device_info
                )
                self.db.add(login_attempt)
                await self.db.commit()
            
            raise
    
    async def create_user_session(
        self,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_info: Optional[Dict[str, Any]] = None,
        remember_me: bool = False
    ) -> Dict[str, Any]:
        """
        Create new user session dengan tokens.
        
        Args:
            user: User object
            ip_address: Client IP
            user_agent: User agent
            device_info: Device information
            remember_me: Extended session duration
            
        Returns:
            Dict dengan session_id, access_token, dan refresh_token
        """
        # Generate tokens
        access_token = security.create_access_token(
            subject=str(user.u_id),
            additional_claims={
                "email": user.u_email,
                "username": user.u_username
            }
        )
        
        # Calculate refresh token expiration
        if remember_me:
            refresh_expires_delta = timedelta(days=90)  # Extended duration
        else:
            refresh_expires_delta = settings.refresh_token_expire_timedelta
        
        refresh_token = security.create_refresh_token(
            subject=str(user.u_id),
            expires_delta=refresh_expires_delta,
            additional_claims={
                "session_id": None  # Will be updated after session creation
            }
        )
        
        # Hash refresh token for storage
        refresh_token_hash = security.hash_token(refresh_token)
        
        # Create session record
        session = UserSession(
            us_user_id=user.u_id,
            us_refresh_token_hash=refresh_token_hash,
            us_expires_at=datetime.now(timezone.utc) + refresh_expires_delta,
            us_ip_address=ip_address,
            us_user_agent=user_agent,
            us_device_info=device_info or {}
        )
        
        self.db.add(session)
        await self.db.flush()  # Get session ID
        
        # Update refresh token with session ID
        refresh_token = security.create_refresh_token(
            subject=str(user.u_id),
            expires_delta=refresh_expires_delta,
            additional_claims={
                "session_id": str(session.us_id)
            }
        )
        
        # Update session with new token hash
        session.us_refresh_token_hash = security.hash_token(refresh_token)
        
        # Audit session creation
        await self.audit_service.log_action(
            action=AuditAction.SESSION_CREATED,
            user_id=user.u_id,
            entity_type="SESSION",
            entity_id=session.us_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return {
            "session_id": session.us_id,
            "access_token": access_token,
            "refresh_token": refresh_token
        }
    
    async def refresh_access_token(
        self,
        refresh_token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Refresh access token menggunakan refresh token.
        
        Args:
            refresh_token: JWT refresh token
            ip_address: Client IP
            user_agent: User agent
            
        Returns:
            Dict dengan access_token baru dan optional refresh_token baru
            
        Raises:
            TokenError: Jika refresh token invalid
        """
        try:
            # Decode refresh token
            payload = security.decode_token(refresh_token, expected_type="refresh")
            user_id = UUID(payload.get("sub"))
            session_id = payload.get("session_id")
            
            if not session_id:
                raise TokenError("Invalid refresh token")
            
            # Hash token untuk lookup
            token_hash = security.hash_token(refresh_token)
            
            # Get session
            result = await self.db.execute(
                select(UserSession)
                .where(
                    and_(
                        UserSession.us_id == UUID(session_id),
                        UserSession.us_refresh_token_hash == token_hash,
                        UserSession.us_is_active == True
                    )
                )
                .options(selectinload(UserSession.user))
            )
            session = result.scalar_one_or_none()
            
            if not session:
                raise TokenError("Invalid or expired refresh token")
            
            # Check if session is expired
            if session.is_expired:
                session.terminate(LogoutReason.TOKEN_EXPIRED)
                await self.db.commit()
                raise TokenError("Refresh token has expired")
            
            # Check if user is still active
            user = session.user
            if not user.u_is_active or user.is_locked_now:
                session.terminate(LogoutReason.ACCOUNT_LOCKED)
                await self.db.commit()
                raise TokenError("Account is not accessible")
            
            # Update session activity
            session.update_activity()
            
            # Generate new access token
            new_access_token = security.create_access_token(
                subject=str(user.u_id),
                additional_claims={
                    "email": user.u_email,
                    "username": user.u_username
                }
            )
            
            # Optionally rotate refresh token (for enhanced security)
            new_refresh_token = None
            if settings.ROTATE_REFRESH_TOKENS:
                # Generate new refresh token
                remaining_time = session.us_expires_at - datetime.now(timezone.utc)
                new_refresh_token = security.create_refresh_token(
                    subject=str(user.u_id),
                    expires_delta=remaining_time,
                    additional_claims={
                        "session_id": str(session.us_id)
                    }
                )
                
                # Update session with new token hash
                session.us_refresh_token_hash = security.hash_token(new_refresh_token)
            
            await self.db.commit()
            
            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "user_id": user.u_id
            }
            
        except TokenError:
            raise
        except Exception as e:
            raise TokenError(f"Failed to refresh token: {str(e)}")
    
    async def logout_user(
        self,
        user_id: UUID,
        refresh_token: Optional[str] = None,
        session_id: Optional[UUID] = None,
        reason: LogoutReason = LogoutReason.USER_INITIATED
    ) -> bool:
        """
        Logout user dari specific session atau current session.
        
        Args:
            user_id: User ID
            refresh_token: Optional refresh token untuk specific session
            session_id: Optional session ID
            reason: Logout reason
            
        Returns:
            True jika berhasil logout
        """
        if refresh_token:
            # Logout specific session berdasarkan refresh token
            token_hash = security.hash_token(refresh_token)
            
            result = await self.db.execute(
                select(UserSession)
                .where(
                    and_(
                        UserSession.us_user_id == user_id,
                        UserSession.us_refresh_token_hash == token_hash,
                        UserSession.us_is_active == True
                    )
                )
            )
            session = result.scalar_one_or_none()
            
            if session:
                session.terminate(reason)
                
                # Audit logout
                await self.audit_service.log_action(
                    action=AuditAction.LOGOUT,
                    user_id=user_id,
                    entity_type="SESSION",
                    entity_id=session.us_id,
                    metadata={"reason": reason}
                )
                
                await self.db.commit()
                return True
                
        elif session_id:
            # Logout specific session by ID
            result = await self.db.execute(
                select(UserSession)
                .where(
                    and_(
                        UserSession.us_id == session_id,
                        UserSession.us_user_id == user_id,
                        UserSession.us_is_active == True
                    )
                )
            )
            session = result.scalar_one_or_none()
            
            if session:
                session.terminate(reason)
                
                # Audit logout
                await self.audit_service.log_action(
                    action=AuditAction.LOGOUT,
                    user_id=user_id,
                    entity_type="SESSION",
                    entity_id=session.us_id,
                    metadata={"reason": reason}
                )
                
                await self.db.commit()
                return True
        
        return False
    
    async def terminate_all_sessions(
        self,
        user_id: UUID,
        reason: LogoutReason = LogoutReason.USER_INITIATED,
        except_session_id: Optional[UUID] = None
    ) -> int:
        """
        Terminate semua active sessions untuk user.
        
        Args:
            user_id: User ID
            reason: Termination reason
            except_session_id: Optional session ID untuk dikecualikan
            
        Returns:
            Jumlah sessions yang di-terminate
        """
        # Get all active sessions
        query = select(UserSession).where(
            and_(
                UserSession.us_user_id == user_id,
                UserSession.us_is_active == True
            )
        )
        
        if except_session_id:
            query = query.where(UserSession.us_id != except_session_id)
        
        result = await self.db.execute(query)
        sessions = result.scalars().all()
        
        # Terminate each session
        terminated_count = 0
        for session in sessions:
            session.terminate(reason)
            terminated_count += 1
        
        if terminated_count > 0:
            # Audit action
            await self.audit_service.log_action(
                action=AuditAction.ALL_SESSIONS_TERMINATED,
                user_id=user_id,
                metadata={
                    "reason": reason,
                    "terminated_count": terminated_count
                }
            )
            
            await self.db.commit()
        
        return terminated_count
    
    async def get_active_sessions(self, user_id: UUID) -> List[UserSession]:
        """
        Get semua active sessions untuk user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of active sessions
        """
        result = await self.db.execute(
            select(UserSession)
            .where(
                and_(
                    UserSession.us_user_id == user_id,
                    UserSession.us_is_active == True,
                    UserSession.us_expires_at > datetime.now(timezone.utc)
                )
            )
            .order_by(UserSession.us_last_activity.desc())
        )
        
        return result.scalars().all()
    
    async def _create_2fa_session(
        self,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> str:
        """
        Create temporary session untuk 2FA verification.
        
        Args:
            user: User object
            ip_address: Client IP
            user_agent: User agent
            
        Returns:
            Temporary session ID
        """
        # Generate temporary session ID
        session_id = secrets.token_urlsafe(32)
        
        # Store in cache/Redis untuk temporary storage
        # Implementasi akan menggunakan Redis service
        # Untuk sementara, return session ID
        
        return session_id
    
    async def get_user_from_2fa_session(self, session_id: str) -> Optional[User]:
        """
        Get user dari temporary 2FA session.
        
        Args:
            session_id: Temporary session ID
            
        Returns:
            User object atau None
        """
        # Implementasi akan menggunakan Redis untuk retrieve user ID
        # Untuk sementara, return None
        return None
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Cleanup expired sessions dari database.
        Bisa dipanggil oleh scheduled job.
        
        Returns:
            Jumlah sessions yang di-cleanup
        """
        # Get expired sessions
        result = await self.db.execute(
            select(UserSession)
            .where(
                or_(
                    UserSession.us_expires_at < datetime.now(timezone.utc),
                    and_(
                        UserSession.us_last_activity.isnot(None),
                        UserSession.us_last_activity < datetime.now(timezone.utc) - timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES)
                    )
                )
            )
        )
        sessions = result.scalars().all()
        
        # Delete expired sessions
        deleted_count = 0
        for session in sessions:
            await self.db.delete(session)
            deleted_count += 1
        
        if deleted_count > 0:
            await self.db.commit()
        
        return deleted_count