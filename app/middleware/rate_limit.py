"""
Rate limiting middleware untuk SecureAuth API.
Menggunakan Redis untuk distributed rate limiting dengan sliding window algorithm.
"""

from typing import Callable, Optional, Dict, Any, Tuple
import time
import hashlib
import json
from datetime import datetime, timedelta

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import redis.asyncio as redis

from app.core.config import settings
from app.core.exceptions import RateLimitError


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Global rate limiting middleware.
    Applies rate limits berdasarkan IP address atau user ID.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        redis_url: Optional[str] = None,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        burst_size: int = 10,
        exclude_paths: Optional[list] = None
    ):
        """
        Initialize rate limit middleware.
        
        Args:
            app: FastAPI/Starlette application
            redis_url: Redis connection URL
            requests_per_minute: Max requests per minute
            requests_per_hour: Max requests per hour
            burst_size: Burst allowance for sudden traffic
            exclude_paths: Paths to exclude from rate limiting
        """
        super().__init__(app)
        self.redis_url = redis_url or str(settings.REDIS_URL)
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.burst_size = burst_size
        self.exclude_paths = exclude_paths or ["/health", "/docs", "/redoc", "/openapi.json"]
        
        # Redis connection will be created per request to avoid connection issues
        self._redis_pool = None
    
    async def get_redis(self) -> redis.Redis:
        """
        Get Redis connection from pool.
        
        Returns:
            Redis connection
        """
        if not self._redis_pool:
            self._redis_pool = redis.ConnectionPool.from_url(
                self.redis_url,
                max_connections=50,
                decode_responses=True
            )
        
        return redis.Redis(connection_pool=self._redis_pool)
    
    def get_identifier(self, request: Request) -> str:
        """
        Get unique identifier for rate limiting.
        
        Args:
            request: Incoming request
            
        Returns:
            Unique identifier (IP or user ID)
        """
        # Try to get user ID from request state (set by auth middleware)
        user_id = getattr(request.state, "user_id", None)
        if user_id:
            return f"user:{user_id}"
        
        # Fallback to IP address
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Get first IP in chain
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"
        
        return f"ip:{client_ip}"
    
    async def check_rate_limit(
        self,
        redis_client: redis.Redis,
        identifier: str,
        window_seconds: int,
        max_requests: int
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check rate limit using sliding window algorithm.
        
        Args:
            redis_client: Redis connection
            identifier: Unique identifier
            window_seconds: Time window in seconds
            max_requests: Maximum requests in window
            
        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        now = time.time()
        window_start = now - window_seconds
        key = f"rate_limit:{window_seconds}:{identifier}"
        
        # Use pipeline for atomic operations
        async with redis_client.pipeline() as pipe:
            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count requests in window
            pipe.zcard(key)
            
            # Get oldest request timestamp
            pipe.zrange(key, 0, 0, withscores=True)
            
            results = await pipe.execute()
            
            request_count = results[1]
            oldest_request = results[2]
            
            # Calculate rate limit info
            rate_limit_info = {
                "limit": max_requests,
                "remaining": max(0, max_requests - request_count),
                "reset": int(now + window_seconds)
            }
            
            # Check if rate limit exceeded
            if request_count >= max_requests:
                # Calculate retry after
                if oldest_request:
                    retry_after = int(oldest_request[0][1] + window_seconds - now)
                else:
                    retry_after = window_seconds
                
                rate_limit_info["retry_after"] = retry_after
                return False, rate_limit_info
            
            # Add current request
            await redis_client.zadd(key, {str(now): now})
            await redis_client.expire(key, window_seconds)
            
            rate_limit_info["remaining"] -= 1
            return True, rate_limit_info
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with rate limiting.
        
        Args:
            request: Incoming request
            call_next: Next middleware/endpoint
            
        Returns:
            Response with rate limit headers
        """
        # Skip rate limiting for excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)
        
        # Skip for OPTIONS requests
        if request.method == "OPTIONS":
            return await call_next(request)
        
        redis_client = None
        try:
            # Get Redis connection
            redis_client = await self.get_redis()
            
            # Get identifier
            identifier = self.get_identifier(request)
            
            # Check minute rate limit
            minute_allowed, minute_info = await self.check_rate_limit(
                redis_client,
                identifier,
                60,
                self.requests_per_minute
            )
            
            if not minute_allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Please try again later.",
                    headers={
                        "Retry-After": str(minute_info["retry_after"]),
                        "X-RateLimit-Limit": str(minute_info["limit"]),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(minute_info["reset"])
                    }
                )
            
            # Check hour rate limit
            hour_allowed, hour_info = await self.check_rate_limit(
                redis_client,
                identifier,
                3600,
                self.requests_per_hour
            )
            
            if not hour_allowed:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Hourly rate limit exceeded. Please try again later.",
                    headers={
                        "Retry-After": str(hour_info["retry_after"]),
                        "X-RateLimit-Limit-Hour": str(hour_info["limit"]),
                        "X-RateLimit-Remaining-Hour": "0",
                        "X-RateLimit-Reset-Hour": str(hour_info["reset"])
                    }
                )
            
            # Process request
            response = await call_next(request)
            
            # Add rate limit headers to response
            response.headers["X-RateLimit-Limit"] = str(minute_info["limit"])
            response.headers["X-RateLimit-Remaining"] = str(minute_info["remaining"])
            response.headers["X-RateLimit-Reset"] = str(minute_info["reset"])
            response.headers["X-RateLimit-Limit-Hour"] = str(hour_info["limit"])
            response.headers["X-RateLimit-Remaining-Hour"] = str(hour_info["remaining"])
            
            return response
            
        except HTTPException:
            raise
        except redis.RedisError as e:
            # Log error but don't block request if Redis is down
            # In production, you might want to implement a circuit breaker
            print(f"Redis error in rate limiting: {e}")
            return await call_next(request)
        except Exception as e:
            print(f"Unexpected error in rate limiting: {e}")
            return await call_next(request)
        finally:
            # Close Redis connection if it was created
            if redis_client:
                await redis_client.close()


class AdaptiveRateLimitMiddleware(RateLimitMiddleware):
    """
    Adaptive rate limiting that adjusts limits based on user behavior and system load.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        base_requests_per_minute: int = 60,
        trusted_user_multiplier: float = 2.0,
        suspicious_user_divisor: float = 2.0
    ):
        """
        Initialize adaptive rate limit middleware.
        
        Args:
            app: FastAPI/Starlette application
            base_requests_per_minute: Base rate limit
            trusted_user_multiplier: Multiplier for trusted users
            suspicious_user_divisor: Divisor for suspicious users
        """
        super().__init__(app, requests_per_minute=base_requests_per_minute)
        self.base_limit = base_requests_per_minute
        self.trusted_multiplier = trusted_user_multiplier
        self.suspicious_divisor = suspicious_user_divisor
    
    async def get_user_trust_score(self, identifier: str, redis_client: redis.Redis) -> float:
        """
        Get trust score for user.
        
        Args:
            identifier: User identifier
            redis_client: Redis connection
            
        Returns:
            Trust score (0.0 to 1.0)
        """
        # This is a simplified implementation
        # In production, you would calculate based on:
        # - Account age
        # - Past behavior
        # - Email verification status
        # - Number of successful requests
        # - Number of rate limit violations
        
        trust_key = f"user_trust:{identifier}"
        trust_score = await redis_client.get(trust_key)
        
        if trust_score:
            return float(trust_score)
        
        # Default trust score
        return 0.5
    
    async def adjust_rate_limit(self, identifier: str, redis_client: redis.Redis) -> int:
        """
        Adjust rate limit based on user trust score.
        
        Args:
            identifier: User identifier
            redis_client: Redis connection
            
        Returns:
            Adjusted rate limit
        """
        trust_score = await self.get_user_trust_score(identifier, redis_client)
        
        if trust_score >= 0.8:
            # Trusted user
            return int(self.base_limit * self.trusted_multiplier)
        elif trust_score <= 0.2:
            # Suspicious user
            return int(self.base_limit / self.suspicious_divisor)
        else:
            # Normal user
            return self.base_limit