"""
Request logging middleware untuk SecureAuth API.
Logs all HTTP requests dengan informasi detail untuk monitoring dan debugging.
"""

from typing import Callable, Optional, Dict, Any
import time
import json
import uuid
import logging
from datetime import datetime, timezone

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings


# Configure logger
logger = logging.getLogger("secureauth.access")


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive request/response logging middleware.
    
    Features:
    - Request ID generation
    - Request/response timing
    - Body logging (dengan filtering untuk sensitive data)
    - Error logging
    - Structured JSON logging
    """
    
    def __init__(
        self,
        app: ASGIApp,
        log_request_body: bool = False,
        log_response_body: bool = False,
        exclude_paths: Optional[list] = None,
        sensitive_fields: Optional[list] = None,
        max_body_size: int = 1024
    ):
        """
        Initialize logging middleware.
        
        Args:
            app: FastAPI/Starlette application
            log_request_body: Whether to log request bodies
            log_response_body: Whether to log response bodies
            exclude_paths: Paths to exclude from logging
            sensitive_fields: Fields to redact from logs
            max_body_size: Maximum body size to log (bytes)
        """
        super().__init__(app)
        self.log_request_body = log_request_body
        self.log_response_body = log_response_body
        self.exclude_paths = exclude_paths or ["/health", "/metrics"]
        self.sensitive_fields = sensitive_fields or [
            "password", "token", "secret", "api_key", "authorization",
            "credit_card", "ssn", "pin", "cvv"
        ]
        self.max_body_size = max_body_size
    
    def should_log_path(self, path: str) -> bool:
        """
        Check if path should be logged.
        
        Args:
            path: Request path
            
        Returns:
            True if path should be logged
        """
        return not any(path.startswith(excluded) for excluded in self.exclude_paths)
    
    def generate_request_id(self) -> str:
        """
        Generate unique request ID.
        
        Returns:
            Request ID
        """
        return str(uuid.uuid4())
    
    def redact_sensitive_data(self, data: Any) -> Any:
        """
        Redact sensitive fields from data.
        
        Args:
            data: Data to redact
            
        Returns:
            Redacted data
        """
        if isinstance(data, dict):
            redacted = {}
            for key, value in data.items():
                if any(sensitive in key.lower() for sensitive in self.sensitive_fields):
                    redacted[key] = "[REDACTED]"
                else:
                    redacted[key] = self.redact_sensitive_data(value)
            return redacted
        elif isinstance(data, list):
            return [self.redact_sensitive_data(item) for item in data]
        else:
            return data
    
    async def get_request_body(self, request: Request) -> Optional[str]:
        """
        Get request body safely.
        
        Args:
            request: Incoming request
            
        Returns:
            Request body as string or None
        """
        if not self.log_request_body:
            return None
        
        try:
            body = await request.body()
            
            # Check size limit
            if len(body) > self.max_body_size:
                return f"[Body too large: {len(body)} bytes]"
            
            # Try to parse as JSON for redaction
            try:
                json_body = json.loads(body)
                redacted_body = self.redact_sensitive_data(json_body)
                return json.dumps(redacted_body)
            except json.JSONDecodeError:
                # Not JSON, return as string (truncated)
                return body.decode('utf-8', errors='ignore')[:self.max_body_size]
        except Exception as e:
            return f"[Error reading body: {str(e)}]"
    
    def create_log_entry(
        self,
        request: Request,
        response: Optional[Response] = None,
        duration_ms: Optional[float] = None,
        error: Optional[Exception] = None,
        request_body: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create structured log entry.
        
        Args:
            request: Incoming request
            response: Response (if available)
            duration_ms: Request duration in milliseconds
            error: Exception (if any)
            request_body: Request body
            
        Returns:
            Log entry dictionary
        """
        # Get client info
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"
        
        # Base log entry
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": getattr(request.state, "request_id", "unknown"),
            "method": request.method,
            "path": request.url.path,
            "query_params": dict(request.query_params),
            "client_ip": client_ip,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "referer": request.headers.get("referer"),
            "host": request.headers.get("host"),
        }
        
        # Add authenticated user if available
        if hasattr(request.state, "user_id"):
            log_entry["user_id"] = str(request.state.user_id)
        
        # Add request body if available
        if request_body:
            log_entry["request_body"] = request_body
        
        # Add response info
        if response:
            log_entry["status_code"] = response.status_code
            log_entry["response_headers"] = dict(response.headers)
            
            # Log response time
            if duration_ms:
                log_entry["duration_ms"] = round(duration_ms, 2)
        
        # Add error info
        if error:
            log_entry["error"] = {
                "type": type(error).__name__,
                "message": str(error),
                "traceback": None  # Add traceback in debug mode if needed
            }
        
        return log_entry
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request with logging.
        
        Args:
            request: Incoming request
            call_next: Next middleware/endpoint
            
        Returns:
            Response
        """
        # Skip logging for excluded paths
        if not self.should_log_path(request.url.path):
            return await call_next(request)
        
        # Generate request ID
        request_id = self.generate_request_id()
        request.state.request_id = request_id
        
        # Start timing
        start_time = time.time()
        
        # Get request body if needed
        request_body = None
        if self.log_request_body and request.method in ["POST", "PUT", "PATCH"]:
            # Store body for logging
            body_bytes = await request.body()
            request_body = await self.get_request_body(request)
            
            # Recreate request with stored body
            async def receive():
                return {"type": "http.request", "body": body_bytes}
            
            request._receive = receive
        
        response = None
        error = None
        
        try:
            # Process request
            response = await call_next(request)
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as e:
            error = e
            raise
            
        finally:
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            
            # Create and log entry
            log_entry = self.create_log_entry(
                request=request,
                response=response,
                duration_ms=duration_ms,
                error=error,
                request_body=request_body
            )
            
            # Log based on status/error
            if error:
                logger.error(json.dumps(log_entry))
            elif response and response.status_code >= 500:
                logger.error(json.dumps(log_entry))
            elif response and response.status_code >= 400:
                logger.warning(json.dumps(log_entry))
            else:
                logger.info(json.dumps(log_entry))


class AccessLogMiddleware(BaseHTTPMiddleware):
    """
    Simplified access log middleware for high-performance logging.
    Logs dalam format yang mirip dengan common log format.
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request dengan simple access logging.
        
        Args:
            request: Incoming request
            call_next: Next middleware/endpoint
            
        Returns:
            Response
        """
        start_time = time.time()
        
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration = time.time() - start_time
        
        # Get client IP
        client_ip = request.client.host if request.client else "-"
        
        # Create log line (Common Log Format style)
        log_line = (
            f'{client_ip} - - [{datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"{request.method} {request.url.path} HTTP/1.1" '
            f'{response.status_code} - '
            f'"{request.headers.get("referer", "-")}" '
            f'"{request.headers.get("user-agent", "-")}" '
            f'{duration:.3f}s'
        )
        
        # Log it
        logger.info(log_line)
        
        return response