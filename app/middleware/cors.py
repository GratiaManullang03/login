"""
CORS middleware untuk SecureAuth API.
Menangani Cross-Origin Resource Sharing dengan konfigurasi yang aman.
"""

from typing import List, Optional, Union, Callable
import re
from urllib.parse import urlparse

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings


class CORSMiddleware(BaseHTTPMiddleware):
    """
    Custom CORS middleware dengan fitur keamanan tambahan.
    
    Features:
    - Dynamic origin validation
    - Credentials support
    - Preflight caching
    - Custom headers configuration
    """
    
    def __init__(
        self,
        app: ASGIApp,
        allow_origins: Optional[List[str]] = None,
        allow_origin_regex: Optional[str] = None,
        allow_credentials: bool = True,
        allow_methods: Optional[List[str]] = None,
        allow_headers: Optional[List[str]] = None,
        expose_headers: Optional[List[str]] = None,
        max_age: int = 600
    ):
        """
        Initialize CORS middleware.
        
        Args:
            app: FastAPI/Starlette application
            allow_origins: List of allowed origins
            allow_origin_regex: Regex pattern for allowed origins
            allow_credentials: Allow credentials in CORS requests
            allow_methods: Allowed HTTP methods
            allow_headers: Allowed request headers
            expose_headers: Headers exposed to the browser
            max_age: Max age for preflight cache (seconds)
        """
        super().__init__(app)
        
        # Use settings if not provided
        self.allow_origins = allow_origins or settings.BACKEND_CORS_ORIGINS
        self.allow_origin_regex = allow_origin_regex
        self.allow_credentials = allow_credentials
        self.allow_methods = allow_methods or ["*"]
        self.allow_headers = allow_headers or ["*"]
        self.expose_headers = expose_headers or []
        self.max_age = max_age
        
        # Compile regex if provided
        self.compiled_origin_regex = None
        if self.allow_origin_regex:
            self.compiled_origin_regex = re.compile(self.allow_origin_regex)
        
        # Normalize origins
        self.allow_all_origins = "*" in self.allow_origins
        self.allow_origins_set = set(self.allow_origins)
    
    def is_allowed_origin(self, origin: str) -> bool:
        """
        Check if origin is allowed.
        
        Args:
            origin: Origin to check
            
        Returns:
            True if origin is allowed
        """
        if self.allow_all_origins:
            return True
        
        if origin in self.allow_origins_set:
            return True
        
        if self.compiled_origin_regex and self.compiled_origin_regex.match(origin):
            return True
        
        return False
    
    def preflight_response(self, request_headers: dict) -> Response:
        """
        Create preflight response for OPTIONS requests.
        
        Args:
            request_headers: Request headers
            
        Returns:
            Preflight response
        """
        response = Response(content="", status_code=200)
        
        # Add CORS headers
        origin = request_headers.get("origin")
        if origin and self.is_allowed_origin(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            
            if self.allow_credentials:
                response.headers["Access-Control-Allow-Credentials"] = "true"
        
        # Add allowed methods
        if self.allow_methods:
            response.headers["Access-Control-Allow-Methods"] = ", ".join(self.allow_methods)
        
        # Add allowed headers
        requested_headers = request_headers.get("access-control-request-headers")
        if requested_headers:
            if "*" in self.allow_headers:
                response.headers["Access-Control-Allow-Headers"] = requested_headers
            else:
                # Filter allowed headers
                allowed = set(h.lower() for h in self.allow_headers)
                requested = set(h.strip().lower() for h in requested_headers.split(","))
                allowed_headers = requested.intersection(allowed)
                if allowed_headers:
                    response.headers["Access-Control-Allow-Headers"] = ", ".join(allowed_headers)
        
        # Add max age
        response.headers["Access-Control-Max-Age"] = str(self.max_age)
        
        # Add Vary header
        response.headers["Vary"] = "Origin"
        
        return response
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process CORS for request.
        
        Args:
            request: Incoming request
            call_next: Next middleware/endpoint
            
        Returns:
            Response with CORS headers
        """
        # Get request headers
        headers = dict(request.headers)
        origin = headers.get("origin")
        
        # Handle preflight
        if request.method == "OPTIONS":
            return self.preflight_response(headers)
        
        # Process request
        response = await call_next(request)
        
        # Add CORS headers to response
        if origin and self.is_allowed_origin(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            
            if self.allow_credentials:
                response.headers["Access-Control-Allow-Credentials"] = "true"
            
            if self.expose_headers:
                response.headers["Access-Control-Expose-Headers"] = ", ".join(self.expose_headers)
        
        # Always add Vary header
        existing_vary = response.headers.get("Vary", "")
        if existing_vary:
            response.headers["Vary"] = f"{existing_vary}, Origin"
        else:
            response.headers["Vary"] = "Origin"
        
        return response


class StrictCORSMiddleware(CORSMiddleware):
    """
    Strict CORS middleware with additional security checks.
    """
    
    def __init__(
        self,
        app: ASGIApp,
        allowed_origins: List[str],
        allowed_methods: List[str] = None,
        allowed_headers: List[str] = None
    ):
        """
        Initialize strict CORS middleware.
        
        Args:
            app: FastAPI/Starlette application
            allowed_origins: Explicit list of allowed origins (no wildcards)
            allowed_methods: Explicit list of allowed methods
            allowed_headers: Explicit list of allowed headers
        """
        # Validate no wildcards
        if "*" in allowed_origins:
            raise ValueError("Wildcards not allowed in strict CORS mode")
        
        super().__init__(
            app=app,
            allow_origins=allowed_origins,
            allow_origin_regex=None,
            allow_credentials=True,
            allow_methods=allowed_methods or ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=allowed_headers or [
                "Accept",
                "Accept-Language",
                "Content-Language",
                "Content-Type",
                "Authorization"
            ],
            expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
            max_age=3600
        )
    
    def is_allowed_origin(self, origin: str) -> bool:
        """
        Strict origin validation with additional checks.
        
        Args:
            origin: Origin to check
            
        Returns:
            True if origin is allowed and valid
        """
        # Parse origin
        try:
            parsed = urlparse(origin)
            
            # Ensure it has a valid scheme
            if parsed.scheme not in ["http", "https"]:
                return False
            
            # Ensure it has a hostname
            if not parsed.hostname:
                return False
            
            # Check against allowed list
            return origin in self.allow_origins_set
            
        except Exception:
            return False