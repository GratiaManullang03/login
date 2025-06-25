"""
Global error handler middleware untuk SecureAuth API.
Menangani semua unhandled exceptions dan mengubahnya menjadi response yang konsisten.
"""

from typing import Callable, Optional, Dict, Any, Union
import traceback
import logging
from datetime import datetime, timezone

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import ValidationError

from app.core.config import settings
from app.core.exceptions import SecureAuthException


# Configure logger
logger = logging.getLogger("secureauth.error")


class ErrorHandlerMiddleware(BaseHTTPMiddleware):
    """
    Global error handler middleware.
    
    Features:
    - Consistent error response format
    - Error logging dengan stack traces
    - Custom error handling untuk berbagai exception types
    - Hide sensitive information in production
    """
    
    def __init__(
        self,
        app: ASGIApp,
        debug: Optional[bool] = None,
        log_errors: bool = True,
        include_request_id: bool = True
    ):
        """
        Initialize error handler middleware.
        
        Args:
            app: FastAPI/Starlette application
            debug: Debug mode (shows stack traces)
            log_errors: Whether to log errors
            include_request_id: Include request ID in error response
        """
        super().__init__(app)
        self.debug = debug if debug is not None else settings.DEBUG
        self.log_errors = log_errors
        self.include_request_id = include_request_id
    
    def create_error_response(
        self,
        request: Request,
        status_code: int,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        error_type: Optional[str] = None,
        stack_trace: Optional[str] = None
    ) -> JSONResponse:
        """
        Create standardized error response.
        
        Args:
            request: Request object
            status_code: HTTP status code
            message: Error message
            details: Additional error details
            error_type: Type of error
            stack_trace: Stack trace (only in debug mode)
            
        Returns:
            JSON error response
        """
        # Base error response
        error_response = {
            "error": {
                "message": message,
                "type": error_type or "Error",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
        
        # Add request ID if available
        if self.include_request_id and hasattr(request.state, "request_id"):
            error_response["error"]["request_id"] = request.state.request_id
        
        # Add details if provided
        if details:
            error_response["error"]["details"] = details
        
        # Add debug information if in debug mode
        if self.debug:
            debug_info = {
                "path": request.url.path,
                "method": request.method,
                "query_params": dict(request.query_params)
            }
            
            if stack_trace:
                debug_info["stack_trace"] = stack_trace.split("\n")
            
            error_response["debug"] = debug_info
        
        return JSONResponse(
            status_code=status_code,
            content=error_response,
            headers={
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store"
            }
        )
    
    def log_error(
        self,
        request: Request,
        error: Exception,
        status_code: int
    ) -> None:
        """
        Log error with context.
        
        Args:
            request: Request object
            error: Exception
            status_code: HTTP status code
        """
        if not self.log_errors:
            return
        
        # Create log entry
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": getattr(request.state, "request_id", "unknown"),
            "method": request.method,
            "path": request.url.path,
            "status_code": status_code,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "client_ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", "unknown")
        }
        
        # Add user ID if available
        if hasattr(request.state, "user_id"):
            log_entry["user_id"] = str(request.state.user_id)
        
        # Log based on severity
        if status_code >= 500:
            logger.error(log_entry, exc_info=True)
        else:
            logger.warning(log_entry)
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request dengan error handling.
        
        Args:
            request: Incoming request
            call_next: Next middleware/endpoint
            
        Returns:
            Response atau error response
        """
        try:
            response = await call_next(request)
            return response
            
        except Exception as exc:
            # Handle different exception types
            return await self.handle_exception(request, exc)
    
    async def handle_exception(self, request: Request, exc: Exception) -> Response:
        """
        Handle specific exception types.
        
        Args:
            request: Request object
            exc: Exception to handle
            
        Returns:
            Error response
        """
        # Get stack trace for logging/debug
        stack_trace = None
        if self.debug or self.log_errors:
            stack_trace = traceback.format_exc()
        
        # Handle SecureAuth custom exceptions
        if isinstance(exc, SecureAuthException):
            self.log_error(request, exc, exc.status_code)
            return self.create_error_response(
                request=request,
                status_code=exc.status_code,
                message=exc.message,
                details=exc.details,
                error_type=type(exc).__name__,
                stack_trace=stack_trace
            )
        
        # Handle FastAPI/Starlette HTTP exceptions
        elif isinstance(exc, (HTTPException, StarletteHTTPException)):
            status_code = exc.status_code
            message = exc.detail
            
            self.log_error(request, exc, status_code)
            return self.create_error_response(
                request=request,
                status_code=status_code,
                message=message,
                error_type="HTTPException",
                stack_trace=stack_trace
            )
        
        # Handle Pydantic validation errors
        elif isinstance(exc, ValidationError):
            self.log_error(request, exc, 422)
            
            # Format validation errors
            errors = []
            for error in exc.errors():
                errors.append({
                    "field": " -> ".join(str(x) for x in error["loc"]),
                    "message": error["msg"],
                    "type": error["type"]
                })
            
            return self.create_error_response(
                request=request,
                status_code=422,
                message="Validation failed",
                details={"validation_errors": errors},
                error_type="ValidationError",
                stack_trace=stack_trace
            )
        
        # Handle all other exceptions
        else:
            self.log_error(request, exc, 500)
            
            # Hide internal error details in production
            if self.debug:
                message = str(exc)
            else:
                message = "An internal server error occurred"
            
            return self.create_error_response(
                request=request,
                status_code=500,
                message=message,
                error_type="InternalServerError",
                stack_trace=stack_trace
            )


class FallbackErrorHandler:
    """
    Fallback error handler untuk menangkap errors yang lolos dari middleware lain.
    Ini adalah last resort error handler.
    """
    
    def __init__(self, app: ASGIApp):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        """
        ASGI application dengan error catching.
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        try:
            await self.app(scope, receive, send)
        except Exception as exc:
            # Log critical error
            logger.critical(
                f"Unhandled exception in application: {type(exc).__name__}: {str(exc)}",
                exc_info=True
            )
            
            # Send basic error response
            response = JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "message": "A critical error occurred",
                        "type": "CriticalError"
                    }
                }
            )
            
            await response(scope, receive, send)