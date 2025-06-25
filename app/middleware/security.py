"""
Security headers middleware untuk SecureAuth API.
Menambahkan berbagai security headers untuk melindungi aplikasi dari common attacks.
"""

from typing import Callable, Optional, Dict, Any
import hashlib
import secrets
import base64

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware untuk menambahkan security headers ke semua response.
    
    Headers yang ditambahkan:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    - X-XSS-Protection: 1; mode=block
    - Strict-Transport-Security (untuk HTTPS)
    - Content-Security-Policy
    - Referrer-Policy
    - Permissions-Policy
    """
    
    def __init__(
        self,
        app: ASGIApp,
        enable_hsts: bool = True,
        enable_csp: bool = True,
        csp_directives: Optional[Dict[str, str]] = None,
        custom_headers: Optional[Dict[str, str]] = None
    ):
        """
        Initialize security headers middleware.
        
        Args:
            app: FastAPI/Starlette application
            enable_hsts: Enable Strict-Transport-Security header
            enable_csp: Enable Content-Security-Policy header
            csp_directives: Custom CSP directives
            custom_headers: Additional custom headers
        """
        super().__init__(app)
        self.enable_hsts = enable_hsts
        self.enable_csp = enable_csp
        self.csp_directives = csp_directives or self._get_default_csp()
        self.custom_headers = custom_headers or {}
    
    def _get_default_csp(self) -> Dict[str, str]:
        """
        Get default Content-Security-Policy directives.
        
        Returns:
            Dictionary of CSP directives
        """
        return {
            "default-src": "'self'",
            "script-src": "'self' 'unsafe-inline' 'unsafe-eval'",  # Adjust based on needs
            "style-src": "'self' 'unsafe-inline'",
            "img-src": "'self' data: https:",
            "font-src": "'self'",
            "connect-src": "'self'",
            "media-src": "'self'",
            "object-src": "'none'",
            "frame-ancestors": "'none'",
            "base-uri": "'self'",
            "form-action": "'self'",
            "upgrade-insecure-requests": ""
        }
    
    def _build_csp_header(self, nonce: Optional[str] = None) -> str:
        """
        Build Content-Security-Policy header value.
        
        Args:
            nonce: Optional nonce for inline scripts
            
        Returns:
            CSP header value
        """
        directives = []
        
        for directive, value in self.csp_directives.items():
            if value:
                # Add nonce to script-src if provided
                if directive == "script-src" and nonce:
                    value = value.replace("'unsafe-inline'", f"'nonce-{nonce}'")
                directives.append(f"{directive} {value}")
            else:
                # For directives without values (like upgrade-insecure-requests)
                directives.append(directive)
        
        return "; ".join(directives)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and add security headers to response.
        
        Args:
            request: Incoming request
            call_next: Next middleware/endpoint
            
        Returns:
            Response with security headers
        """
        # Generate CSP nonce if needed
        nonce = None
        if self.enable_csp and "'unsafe-inline'" in self.csp_directives.get("script-src", ""):
            nonce = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
            # Store nonce in request state for use in templates
            request.state.csp_nonce = nonce
        
        # Process request
        response = await call_next(request)
        
        # Add security headers
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        }
        
        # Add HSTS for HTTPS connections
        if self.enable_hsts and request.url.scheme == "https":
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        
        # Add CSP
        if self.enable_csp:
            headers["Content-Security-Policy"] = self._build_csp_header(nonce)
        
        # Add custom headers
        headers.update(self.custom_headers)
        
        # Apply headers to response
        for header, value in headers.items():
            response.headers[header] = value
        
        # Remove sensitive headers
        sensitive_headers = ["Server", "X-Powered-By"]
        for header in sensitive_headers:
            if header in response.headers:
                del response.headers[header]
        
        return response


class CSPNonceMiddleware(BaseHTTPMiddleware):
    """
    Specialized middleware for CSP nonce generation and management.
    Use this when you need fine-grained control over CSP nonces.
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Generate and attach CSP nonce to request.
        
        Args:
            request: Incoming request
            call_next: Next middleware/endpoint
            
        Returns:
            Response with CSP nonce header
        """
        # Generate nonce
        nonce = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
        request.state.csp_nonce = nonce
        
        # Process request
        response = await call_next(request)
        
        # Update CSP header with nonce if exists
        if "Content-Security-Policy" in response.headers:
            csp = response.headers["Content-Security-Policy"]
            # Replace unsafe-inline with nonce
            csp = csp.replace("'unsafe-inline'", f"'nonce-{nonce}'")
            response.headers["Content-Security-Policy"] = csp
        
        return response


class SecurityMiddleware:
    """
    Comprehensive security middleware that combines multiple security features.
    """
    
    def __init__(self, app: ASGIApp):
        """
        Initialize comprehensive security middleware.
        
        Args:
            app: FastAPI/Starlette application
        """
        self.app = app
        
        # Chain security middleware
        self.app = SecurityHeadersMiddleware(
            self.app,
            enable_hsts=not settings.DEBUG,
            enable_csp=True
        )