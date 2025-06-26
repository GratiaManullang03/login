"""
Token service untuk SecureAuth API.
Menangani creation, validation, dan management berbagai jenis tokens.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, delete, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload 
from app.core.config import settings
from app.core.security import security
from app.core.constants import TokenType
from app.core.exceptions import (
    TokenError,
    ExpiredTokenException,
    InvalidTokenException,
    NotFoundError
)
from app.models.user import User
from app.models.token import UserToken


class TokenService:
    """
    Service class untuk token operations.
    Menangani berbagai jenis tokens: email verification, password reset, API keys, etc.
    """
    
    def __init__(self, db: AsyncSession):
        """
        Initialize token service.
        
        Args:
            db: Database session
        """
        self.db = db
    
    async def create_token(
        self,
        user_id: UUID,
        token_type: TokenType,
        expires_delta: Optional[timedelta] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create new token untuk user.
        
        Args:
            user_id: User ID
            token_type: Type of token
            expires_delta: Custom expiration time
            metadata: Additional token metadata
            
        Returns:
            Generated token string
            
        Raises:
            NotFoundError: Jika user tidak ditemukan
        """
        # Verify user exists
        result = await self.db.execute(
            select(User).where(User.u_id == user_id)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise NotFoundError("User not found")
        
        # Invalidate existing tokens of same type
        await self._invalidate_existing_tokens(user_id, token_type)
        
        # Generate token
        token_value = security.generate_secure_token()
        
        # Determine expiration
        if expires_delta:
            expires_at = datetime.now(timezone.utc) + expires_delta
        else:
            # Default expiration based on token type
            if token_type == TokenType.EMAIL_VERIFICATION:
                expires_at = datetime.now(timezone.utc) + settings.email_verification_expire_timedelta
            elif token_type == TokenType.PASSWORD_RESET:
                expires_at = datetime.now(timezone.utc) + settings.password_reset_expire_timedelta
            else:
                # Default 24 hours
                expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        
        # Hash token for storage
        token_hash = security.hash_token(token_value)
        
        # Create token record
        user_token = UserToken(
            ut_user_id=user_id,
            ut_token_hash=token_hash,
            ut_token_type=token_type,
            ut_expires_at=expires_at,
            ut_metadata=metadata or {}
        )
        
        self.db.add(user_token)
        
        try:
            await self.db.commit()
            return token_value
        except IntegrityError:
            await self.db.rollback()
            raise TokenError("Failed to create token")
    
    async def verify_token(
        self,
        token: str,
        token_type: TokenType,
        mark_as_used: bool = True
    ) -> UserToken:
        """
        Verify token dan return token object.
        
        Args:
            token: Token string to verify
            token_type: Expected token type
            mark_as_used: Whether to mark token as used
            
        Returns:
            UserToken object
            
        Raises:
            InvalidTokenException: Jika token tidak valid
            ExpiredTokenException: Jika token expired
        """
        # Hash token untuk lookup
        token_hash = security.hash_token(token)
        
        # Find token
        result = await self.db.execute(
            select(UserToken)
            .where(
                and_(
                    UserToken.ut_token_hash == token_hash,
                    UserToken.ut_token_type == token_type
                )
            )
            .options(selectinload(UserToken.user))
        )
        user_token = result.scalar_one_or_none()
        
        if not user_token:
            raise InvalidTokenException("Invalid token")
        
        # Check if already used
        if user_token.ut_is_used:
            raise InvalidTokenException("Token has already been used")
        
        # Check expiration
        if user_token.is_expired:
            raise ExpiredTokenException("Token has expired")
        
        # Mark as used if requested
        if mark_as_used:
            user_token.mark_as_used()
            await self.db.commit()
        
        return user_token
    
    async def verify_and_use_token(
        self,
        token: str,
        token_type: TokenType
    ) -> User:
        """
        Verify token, mark as used, dan return associated user.
        
        Args:
            token: Token string
            token_type: Expected token type
            
        Returns:
            User object
            
        Raises:
            InvalidTokenException: Jika token tidak valid
            ExpiredTokenException: Jika token expired
        """
        user_token = await self.verify_token(token, token_type, mark_as_used=True)
        return user_token.user
    
    async def create_api_key(
        self,
        user_id: UUID,
        name: str,
        expires_in_days: Optional[int] = None,
        scopes: Optional[List[str]] = None
    ) -> Tuple[str, UserToken]:
        """
        Create API key untuk user.
        
        Args:
            user_id: User ID
            name: API key name/description
            expires_in_days: Expiration in days
            scopes: API key scopes/permissions
            
        Returns:
            Tuple of (api_key_string, token_object)
        """
        # Generate API key with prefix
        key_value = f"sk_live_{security.generate_secure_token(48)}"
        
        # Set expiration
        if expires_in_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
        else:
            # No expiration for API keys by default
            expires_at = datetime.now(timezone.utc) + timedelta(days=36500)  # 100 years
        
        # Create token with metadata
        metadata = {
            "name": name,
            "scopes": scopes or [],
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Hash key for storage
        key_hash = security.hash_token(key_value)
        
        # Create token record
        api_token = UserToken(
            ut_user_id=user_id,
            ut_token_hash=key_hash,
            ut_token_type=TokenType.API_KEY,
            ut_expires_at=expires_at,
            ut_metadata=metadata
        )
        
        self.db.add(api_token)
        await self.db.commit()
        
        return key_value, api_token
    
    async def verify_api_key(self, api_key: str) -> Tuple[User, List[str]]:
        """
        Verify API key dan return user dengan scopes.
        
        Args:
            api_key: API key string
            
        Returns:
            Tuple of (user, scopes)
            
        Raises:
            InvalidTokenException: Jika API key tidak valid
        """
        # Hash key untuk lookup
        key_hash = security.hash_token(api_key)
        
        # Find API key
        result = await self.db.execute(
            select(UserToken)
            .where(
                and_(
                    UserToken.ut_token_hash == key_hash,
                    UserToken.ut_token_type == TokenType.API_KEY,
                    UserToken.ut_is_used == False
                )
            )
            .options(selectinload(UserToken.user))
        )
        api_token = result.scalar_one_or_none()
        
        if not api_token:
            raise InvalidTokenException("Invalid API key")
        
        # Check expiration
        if api_token.is_expired:
            raise ExpiredTokenException("API key has expired")
        
        # Check if user is active
        if not api_token.user.u_is_active:
            raise InvalidTokenException("User account is not active")
        
        # Get scopes from metadata
        scopes = api_token.ut_metadata.get("scopes", []) if api_token.ut_metadata else []
        
        # Update last used timestamp
        api_token.ut_metadata["last_used_at"] = datetime.now(timezone.utc).isoformat()
        await self.db.commit()
        
        return api_token.user, scopes
    
    async def revoke_token(
        self,
        token_id: UUID,
        user_id: UUID
    ) -> bool:
        """
        Revoke specific token.
        
        Args:
            token_id: Token ID to revoke
            user_id: User ID (untuk verifikasi ownership)
            
        Returns:
            True jika berhasil
            
        Raises:
            NotFoundError: Jika token tidak ditemukan
        """
        # Get token
        result = await self.db.execute(
            select(UserToken)
            .where(
                and_(
                    UserToken.ut_id == token_id,
                    UserToken.ut_user_id == user_id
                )
            )
        )
        token = result.scalar_one_or_none()
        
        if not token:
            raise NotFoundError("Token not found")
        
        # Mark as used (effectively revoking it)
        token.mark_as_used()
        await self.db.commit()
        
        return True
    
    async def revoke_all_tokens(
        self,
        user_id: UUID,
        token_type: Optional[TokenType] = None
    ) -> int:
        """
        Revoke semua tokens untuk user.
        
        Args:
            user_id: User ID
            token_type: Optional specific token type to revoke
            
        Returns:
            Number of tokens revoked
        """
        query = select(UserToken).where(
            and_(
                UserToken.ut_user_id == user_id,
                UserToken.ut_is_used == False
            )
        )
        
        if token_type:
            query = query.where(UserToken.ut_token_type == token_type)
        
        result = await self.db.execute(query)
        tokens = result.scalars().all()
        
        revoked_count = 0
        for token in tokens:
            token.mark_as_used()
            revoked_count += 1
        
        if revoked_count > 0:
            await self.db.commit()
        
        return revoked_count
    
    async def get_user_tokens(
        self,
        user_id: UUID,
        token_type: Optional[TokenType] = None,
        include_used: bool = False
    ) -> List[UserToken]:
        """
        Get tokens untuk user.
        
        Args:
            user_id: User ID
            token_type: Optional filter by token type
            include_used: Whether to include used tokens
            
        Returns:
            List of tokens
        """
        query = select(UserToken).where(UserToken.ut_user_id == user_id)
        
        if token_type:
            query = query.where(UserToken.ut_token_type == token_type)
        
        if not include_used:
            query = query.where(UserToken.ut_is_used == False)
        
        query = query.order_by(UserToken.created_at.desc())
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def cleanup_expired_tokens(self) -> int:
        """
        Cleanup expired tokens dari database.
        Bisa dipanggil oleh scheduled job.
        
        Returns:
            Number of tokens deleted
        """
        # Delete expired and used tokens older than 30 days
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)
        
        result = await self.db.execute(
            delete(UserToken)
            .where(
                or_(
                    and_(
                        UserToken.ut_expires_at < datetime.now(timezone.utc),
                        UserToken.created_at < cutoff_date
                    ),
                    and_(
                        UserToken.ut_is_used == True,
                        UserToken.ut_used_at < cutoff_date
                    )
                )
            )
        )
        
        deleted_count = result.rowcount
        
        if deleted_count > 0:
            await self.db.commit()
        
        return deleted_count
    
    async def _invalidate_existing_tokens(
        self,
        user_id: UUID,
        token_type: TokenType
    ) -> None:
        """
        Invalidate existing tokens of same type untuk user.
        
        Args:
            user_id: User ID
            token_type: Token type to invalidate
        """
        # Mark existing tokens as used
        result = await self.db.execute(
            select(UserToken)
            .where(
                and_(
                    UserToken.ut_user_id == user_id,
                    UserToken.ut_token_type == token_type,
                    UserToken.ut_is_used == False
                )
            )
        )
        tokens = result.scalars().all()
        
        for token in tokens:
            token.mark_as_used()