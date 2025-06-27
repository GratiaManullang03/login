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
    - API endpoints exemption for Bearer auth
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
        exclude_paths: Set[str] = None,
        api_paths_with_bearer: Set[str] = None
    ):
        super().__init__(app)
        self.secret_key = secret_key or settings.CSRF_SECRET or settings.SECRET_KEY
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.form_field_name = form_field_name
        self.safe_methods = safe_methods or {"GET", "HEAD", "OPTIONS", "TRACE"}
        self.token_ttl = token_ttl
        self.exclude_paths = exclude_paths or {
            "/docs", 
            "/redoc", 
            "/openapi.json", 
            "/health",
            "/api/v1/health",
            "/api/v1/auth/csrf-token"  # CSRF token endpoint itself
        }
        # API paths that use Bearer authentication (exempt from CSRF)
        self.api_paths_with_bearer = api_paths_with_bearer or {
            "/api/v1/auth/logout",
            "/api/v1/auth/logout/all",
            "/api/v1/auth/refresh",
            "/api/v1/users",
            "/api/v1/admin"
        }
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
        
        # Check if this is an API endpoint with Bearer authentication
        if await self._is_api_request_with_bearer(request):
            # Skip CSRF for API endpoints that use Bearer token authentication
            return await call_next(request)
        
        # Verify CSRF token for unsafe methods
        if not await self._verify_csrf_token(request):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF verification failed"
            )
        
        response = await call_next(request)
        return response
    
    async def _is_api_request_with_bearer(self, request: Request) -> bool:
        """
        Check if request is to an API endpoint with Bearer authentication.
        
        Returns True if:
        1. Path matches API paths that use Bearer auth
        2. Request has Authorization header with Bearer token
        """
        # Check if path is in API paths list
        path_matches = any(
            request.url.path.startswith(path) 
            for path in self.api_paths_with_bearer
        )
        
        if not path_matches:
            return False
        
        # Check for Bearer token in Authorization header
        auth_header = request.headers.get("Authorization", "")
        return auth_header.startswith("Bearer ")
    
    async def _ensure_csrf_cookie(self, request: Request, response: Response) -> None:
        """Ensure CSRF cookie is set."""
        if self.cookie_name not in request.cookies:
            token = self.generate_csrf_token()
            response.set_cookie(
                key=self.cookie_name,
                value=token,
                max_age=self.token_ttl,
                httponly=False,  # Must be False for JavaScript access
                secure=settings.USE_SECURE_COOKIES and not settings.DEBUG,
                samesite="lax",
                path="/"
            )
    
    async def _verify_csrf_token(self, request: Request) -> bool:
        """
        Verify CSRF token from request.
        
        Token can be provided in:
        1. Header: X-CSRF-Token
        2. Form data: csrf_token
        3. JSON body: csrf_token
        """
        # Get token from cookie
        cookie_token = request.cookies.get(self.cookie_name)
        if not cookie_token:
            return False
        
        # Get token from request (header, form, or JSON)
        request_token = None
        
        # Try header first
        request_token = request.headers.get(self.header_name)
        
        # Try form data
        if not request_token and request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
            form_data = await request.form()
            request_token = form_data.get(self.form_field_name)
        
        # Try JSON body
        if not request_token and request.headers.get("content-type", "").startswith("application/json"):
            try:
                body = await request.body()
                if body:
                    import json
                    data = json.loads(body)
                    request_token = data.get(self.form_field_name)
                    # Reset body for downstream processing
                    request._body = body
            except:
                pass
        
        if not request_token:
            return False
        
        # Validate tokens match and are not expired
        return self.validate_csrf_token(cookie_token) and cookie_token == request_token
    
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


def get_csrf_token(request: Request) -> Optional[str]:
    """
    Get CSRF token from request cookies.
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