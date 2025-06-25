"""
Rate limiting dependencies untuk FastAPI.
Menggunakan Redis untuk distributed rate limiting.
"""

from typing import Optional, Callable
from datetime import datetime, timedelta
import hashlib

from fastapi import Request, HTTPException, status
import redis.asyncio as redis

from app.core.config import settings
from app.core.exceptions import RateLimitError


class RateLimitDependency:
    """
    Rate limiting dependency menggunakan sliding window algorithm.
    """
    
    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        namespace: str = "api",
        key_func: Optional[Callable[[Request], str]] = None
    ):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed dalam window
            window_seconds: Time window dalam seconds
            namespace: Namespace untuk Redis keys
            key_func: Custom function untuk generate rate limit key
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.namespace = namespace
        self.key_func = key_func or self._default_key_func
    
    def _default_key_func(self, request: Request) -> str:
        """
        Default key function menggunakan client IP.
        
        Args:
            request: FastAPI request
            
        Returns:
            Rate limit key
        """
        client_ip = request.client.host if request.client else "unknown"
        return f"{self.namespace}:{client_ip}"
    
    async def __call__(self, request: Request) -> None:
        """
        Check rate limit untuk request.
        
        Args:
            request: FastAPI request
            
        Raises:
            HTTPException: Jika rate limit exceeded
        """
        # Get Redis connection
        redis_client = redis.from_url(
            str(settings.REDIS_URL),
            encoding="utf-8",
            decode_responses=True
        )
        
        try:
            # Generate key
            key = self.key_func(request)
            
            # Current timestamp
            now = datetime.now().timestamp()
            window_start = now - self.window_seconds
            
            # Remove old entries
            await redis_client.zremrangebyscore(key, 0, window_start)
            
            # Count requests in window
            request_count = await redis_client.zcard(key)
            
            if request_count >= self.max_requests:
                # Calculate retry after
                oldest_request = await redis_client.zrange(key, 0, 0, withscores=True)
                if oldest_request:
                    retry_after = int(oldest_request[0][1] + self.window_seconds - now)
                else:
                    retry_after = self.window_seconds
                
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded",
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(self.max_requests),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(now + retry_after))
                    }
                )
            
            # Add current request
            await redis_client.zadd(key, {str(now): now})
            
            # Set expiry
            await redis_client.expire(key, self.window_seconds)
            
            # Add rate limit headers to response
            request.state.rate_limit_headers = {
                "X-RateLimit-Limit": str(self.max_requests),
                "X-RateLimit-Remaining": str(self.max_requests - request_count - 1),
                "X-RateLimit-Reset": str(int(now + self.window_seconds))
            }
            
        finally:
            await redis_client.close()


class IPBasedRateLimiter(RateLimitDependency):
    """
    IP-based rate limiter dengan default settings.
    """
    
    def __init__(self, namespace: str = "api"):
        super().__init__(
            max_requests=settings.RATE_LIMIT_PER_MINUTE,
            window_seconds=60,
            namespace=namespace
        )


class UserBasedRateLimiter(RateLimitDependency):
    """
    User-based rate limiter (requires authentication).
    """
    
    def __init__(
        self,
        max_requests: int,
        window_seconds: int,
        namespace: str = "user"
    ):
        super().__init__(
            max_requests=max_requests,
            window_seconds=window_seconds,
            namespace=namespace,
            key_func=self._user_key_func
        )
    
    def _user_key_func(self, request: Request) -> str:
        """
        Generate key based on authenticated user.
        
        Args:
            request: FastAPI request
            
        Returns:
            Rate limit key
        """
        # Get user ID from request state (set by auth middleware)
        user_id = getattr(request.state, "user_id", None)
        if user_id:
            return f"{self.namespace}:{user_id}"
        
        # Fallback to IP
        client_ip = request.client.host if request.client else "unknown"
        return f"{self.namespace}:ip:{client_ip}"