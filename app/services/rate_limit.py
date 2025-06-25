"""
Rate limiting service untuk SecureAuth API.
Menangani rate limiting logic dengan Redis backend.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
import redis.asyncio as redis
import json

from app.core.config import settings
from app.core.exceptions import RateLimitError


class RateLimitService:
    """
    Service class untuk rate limiting operations.
    Menggunakan sliding window algorithm dengan Redis.
    """
    
    def __init__(self, redis_url: Optional[str] = None):
        """
        Initialize rate limit service.
        
        Args:
            redis_url: Redis connection URL
        """
        self.redis_url = redis_url or str(settings.REDIS_URL)
        self._redis_client = None
    
    async def get_redis(self) -> redis.Redis:
        """
        Get Redis client (lazy initialization).
        
        Returns:
            Redis client
        """
        if not self._redis_client:
            self._redis_client = redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
        return self._redis_client
    
    async def check_rate_limit(
        self,
        key: str,
        limit: int,
        window_seconds: int
    ) -> Tuple[bool, Dict[str, int]]:
        """
        Check if rate limit is exceeded.
        
        Args:
            key: Unique key for rate limiting (e.g., user:123 or ip:1.2.3.4)
            limit: Maximum requests allowed
            window_seconds: Time window in seconds
            
        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        redis_client = await self.get_redis()
        
        now = datetime.now().timestamp()
        window_start = now - window_seconds
        
        # Redis key dengan namespace
        redis_key = f"rate_limit:{window_seconds}:{key}"
        
        # Pipeline untuk atomic operations
        async with redis_client.pipeline() as pipe:
            # Remove old entries
            pipe.zremrangebyscore(redis_key, 0, window_start)
            
            # Count current requests
            pipe.zcard(redis_key)
            
            # Execute pipeline
            results = await pipe.execute()
            current_count = results[1]
            
            # Check if limit exceeded
            if current_count >= limit:
                # Get oldest request to calculate retry-after
                oldest = await redis_client.zrange(
                    redis_key, 0, 0, withscores=True
                )
                
                if oldest:
                    retry_after = int(oldest[0][1] + window_seconds - now)
                else:
                    retry_after = window_seconds
                
                return False, {
                    "limit": limit,
                    "remaining": 0,
                    "reset": int(now + retry_after),
                    "retry_after": retry_after
                }
            
            # Add current request
            await redis_client.zadd(redis_key, {str(now): now})
            await redis_client.expire(redis_key, window_seconds)
            
            return True, {
                "limit": limit,
                "remaining": limit - current_count - 1,
                "reset": int(now + window_seconds),
                "retry_after": None
            }
    
    async def check_login_rate_limit(
        self,
        identifier: str,
        ip_address: str
    ) -> Tuple[bool, Dict[str, int]]:
        """
        Check rate limit specifically untuk login attempts.
        Checks both per-user dan per-IP limits.
        
        Args:
            identifier: User identifier (email atau username)
            ip_address: Client IP address
            
        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        # Check per-IP limit
        ip_allowed, ip_info = await self.check_rate_limit(
            key=f"login:ip:{ip_address}",
            limit=settings.LOGIN_RATE_LIMIT_PER_MINUTE,
            window_seconds=60
        )
        
        if not ip_allowed:
            return False, ip_info
        
        # Check per-identifier limit (more strict)
        id_allowed, id_info = await self.check_rate_limit(
            key=f"login:id:{identifier}",
            limit=settings.LOGIN_RATE_LIMIT_PER_MINUTE // 2,  # Half the IP limit
            window_seconds=60
        )
        
        return id_allowed, id_info
    
    async def check_api_rate_limit(
        self,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        endpoint: Optional[str] = None
    ) -> Tuple[bool, Dict[str, int]]:
        """
        Check API rate limit dengan berbagai strategies.
        
        Args:
            user_id: User ID untuk authenticated requests
            ip_address: IP address untuk anonymous requests
            endpoint: Specific endpoint untuk per-endpoint limits
            
        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        # Determine key dan limits
        if user_id:
            # Authenticated user limits (more generous)
            key = f"api:user:{user_id}"
            per_minute = settings.RATE_LIMIT_PER_MINUTE * 2
            per_hour = settings.RATE_LIMIT_PER_HOUR * 2
        else:
            # Anonymous IP-based limits
            key = f"api:ip:{ip_address}"
            per_minute = settings.RATE_LIMIT_PER_MINUTE
            per_hour = settings.RATE_LIMIT_PER_HOUR
        
        # Check per-minute limit
        minute_allowed, minute_info = await self.check_rate_limit(
            key=key,
            limit=per_minute,
            window_seconds=60
        )
        
        if not minute_allowed:
            return False, minute_info
        
        # Check per-hour limit
        hour_allowed, hour_info = await self.check_rate_limit(
            key=key,
            limit=per_hour,
            window_seconds=3600
        )
        
        if not hour_allowed:
            return False, hour_info
        
        # Check endpoint-specific limits if provided
        if endpoint:
            endpoint_allowed, endpoint_info = await self.check_rate_limit(
                key=f"{key}:endpoint:{endpoint}",
                limit=10,  # Strict per-endpoint limit
                window_seconds=60
            )
            
            if not endpoint_allowed:
                return False, endpoint_info
        
        # Return the most restrictive info
        return True, minute_info
    
    async def reset_rate_limit(self, key: str, window_seconds: int) -> bool:
        """
        Reset rate limit untuk specific key.
        Useful untuk testing atau admin override.
        
        Args:
            key: Rate limit key
            window_seconds: Window to reset
            
        Returns:
            True jika berhasil
        """
        redis_client = await self.get_redis()
        redis_key = f"rate_limit:{window_seconds}:{key}"
        
        await redis_client.delete(redis_key)
        return True
    
    async def get_rate_limit_info(
        self,
        key: str,
        limit: int,
        window_seconds: int
    ) -> Dict[str, Any]:
        """
        Get current rate limit info tanpa incrementing counter.
        
        Args:
            key: Rate limit key
            limit: Maximum allowed
            window_seconds: Time window
            
        Returns:
            Rate limit information
        """
        redis_client = await self.get_redis()
        
        now = datetime.now().timestamp()
        window_start = now - window_seconds
        redis_key = f"rate_limit:{window_seconds}:{key}"
        
        # Clean old entries dan count
        async with redis_client.pipeline() as pipe:
            pipe.zremrangebyscore(redis_key, 0, window_start)
            pipe.zcard(redis_key)
            results = await pipe.execute()
            
        current_count = results[1]
        
        return {
            "limit": limit,
            "used": current_count,
            "remaining": max(0, limit - current_count),
            "reset": int(now + window_seconds),
            "window_seconds": window_seconds
        }
    
    async def close(self):
        """Close Redis connection."""
        if self._redis_client:
            await self._redis_client.close()