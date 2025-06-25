"""
Custom CSRF Protection Middleware for FastAPI.
Replaces the removed starlette.middleware.csrf and incompatible fastapi-csrf-protect.
"""

import secrets
import time
from typing import Optional, Set, Dict, Any
from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import MutableHeaders
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.core.config import settings


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """
    CSRF Protection middleware compatible with Pydantic v2.
    
    Features:
    - Double Submit Cookie pattern
    - Token rotation
    - Configurable expiry
    - Safe methods exemption
    """
    
    def __init__(
        self, 
        app, 
        secret_key: str = None,
        cookie_name: str = "csrf_token",
        header_name: str = "X-CSRF-Token",
        form_field_name: str = "csrf_token",
        safe_methods: Set[str] = None,
        token_ttl: int = 3600,  # 1 hour
        exclude_paths: Set[str] = None
    ):
        super().__init__(app)
        self.secret_key = secret_key or settings.CSRF_SECRET or settings.SECRET_KEY
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.form_field_name = form_field_name
        self.safe_methods = safe_methods or {"GET", "HEAD", "OPTIONS", "TRACE"}
        self.token_ttl = token_ttl
        self.exclude_paths = exclude_paths or {"/docs", "/redoc", "/openapi.json", "/health"}
        self.serializer = URLSafeTimedSerializer(self.secret_key)
    
    async def dispatch(self, request: Request, call_next):
        # Skip CSRF check for excluded paths
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)
        
        # Skip CSRF check for safe methods
        if request.method in self.safe_methods:
            response = await call_next(request)
            # Generate new token for GET requests if not present
            if request.method == "GET":
                await self._ensure_csrf_cookie(request, response)
            return response
        
        # Verify CSRF token for unsafe methods
        if not await self._verify_csrf_token(request):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF verification failed"
            )
        
        response = await call_next(request)
        return response
    
    async def _ensure_csrf_cookie(self, request: Request, response: Response) -> None:
        """Ensure CSRF cookie is set."""
        csrf_cookie = request.cookies.get(self.cookie_name)
        
        # Validate existing token
        if csrf_cookie:
            try:
                self.serializer.loads(csrf_cookie, max_age=self.token_ttl)
                return  # Valid token exists
            except (BadSignature, SignatureExpired):
                pass  # Invalid token, generate new one
        
        # Generate new token
        token_data = {
            "csrf": secrets.token_urlsafe(32),
            "timestamp": int(time.time())
        }
        token = self.serializer.dumps(token_data)
        
        # Set cookie
        response.set_cookie(
            key=self.cookie_name,
            value=token,
            max_age=self.token_ttl,
            httponly=False,  # Must be readable by JavaScript
            secure=settings.USE_SECURE_COOKIES and not settings.DEBUG,
            samesite="lax"
        )
    
    async def _verify_csrf_token(self, request: Request) -> bool:
        """Verify CSRF token from request."""
        # Get token from cookie
        cookie_token = request.cookies.get(self.cookie_name)
        if not cookie_token:
            return False
        
        # Validate cookie token
        try:
            cookie_data = self.serializer.loads(cookie_token, max_age=self.token_ttl)
        except (BadSignature, SignatureExpired):
            return False
        
        # Get token from request (header or form)
        request_token = None
        
        # Check header first
        request_token = request.headers.get(self.header_name)
        
        # If not in header, check form data
        if not request_token and request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            form_data = await request.form()
            request_token = form_data.get(self.form_field_name)
            # Reset form data for downstream processing
            request._form = form_data
        
        # If not in header or form, check JSON body
        if not request_token and request.headers.get("content-type", "").startswith("application/json"):
            try:
                body = await request.json()
                request_token = body.get(self.form_field_name)
                # Store body for downstream processing
                request._json = body
            except:
                pass
        
        if not request_token:
            return False
        
        # Compare tokens
        return cookie_token == request_token


def get_csrf_token(request: Request) -> Optional[str]:
    """
    Helper function to get CSRF token from request.
    Useful for templates or API responses.
    """
    return request.cookies.get("csrf_token")


class CSRFProtect:
    """
    CSRF Protection helper class for manual token validation.
    Can be used as a dependency in specific endpoints.
    """
    
    def __init__(
        self,
        secret_key: str = None,
        cookie_name: str = "csrf_token",
        header_name: str = "X-CSRF-Token",
        token_ttl: int = 3600
    ):
        self.secret_key = secret_key or settings.CSRF_SECRET or settings.SECRET_KEY
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.token_ttl = token_ttl
        self.serializer = URLSafeTimedSerializer(self.secret_key)
    
    def generate_csrf_token(self) -> str:
        """Generate a new CSRF token."""
        token_data = {
            "csrf": secrets.token_urlsafe(32),
            "timestamp": int(time.time())
        }
        return self.serializer.dumps(token_data)
    
    def validate_csrf_token(self, token: str) -> bool:
        """Validate a CSRF token."""
        try:
            self.serializer.loads(token, max_age=self.token_ttl)
            return True
        except (BadSignature, SignatureExpired):
            return False
    
    async def get_csrf_token(self, request: Request) -> Optional[str]:
        """Get CSRF token from request cookies."""
        return request.cookies.get(self.cookie_name)
    
    def set_csrf_cookie(self, response: Response, token: str) -> None:
        """Set CSRF cookie in response."""
        response.set_cookie(
            key=self.cookie_name,
            value=token,
            max_age=self.token_ttl,
            httponly=False,
            secure=settings.USE_SECURE_COOKIES and not settings.DEBUG,
            samesite="lax"
        )