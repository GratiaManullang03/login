"""
Main application entry point untuk SecureAuth API.
Mengkonfigurasi FastAPI application dengan semua middleware, routers, dan handlers.
"""

import logging
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.csrf import CSRFMiddleware

from app.core.config import settings
from app.core.exceptions import SecureAuthException
from app.db.session import init_db, close_db
from app.api.v1 import auth, users, health
from app.middleware.security import SecurityHeadersMiddleware
from app.middleware.logging import LoggingMiddleware
from app.middleware.error_handler import ErrorHandlerMiddleware
from app.middleware.rate_limit import RateLimitMiddleware

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format=settings.LOG_FORMAT
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    """
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    
    # Initialize database
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise
    
    # Initialize other services if needed
    # e.g., Redis, background tasks, etc.
    
    logger.info("Application startup complete")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")
    
    # Close database connections
    await close_db()
    
    # Cleanup other resources
    # e.g., Redis connections, background tasks, etc.
    
    logger.info("Application shutdown complete")


def create_application() -> FastAPI:
    """
    Create and configure FastAPI application.
    
    Returns:
        Configured FastAPI application
    """
    # Create FastAPI instance
    app = FastAPI(
        title=settings.APP_NAME,
        description="Secure Authentication and Identity Management API",
        version=settings.APP_VERSION,
        docs_url="/docs" if settings.DEBUG else None,  # Disable in production
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
        lifespan=lifespan
    )
    
    # Add middleware (order matters - executed in reverse order)
    
    # 1. Error Handler (catches all exceptions)
    app.add_middleware(
        ErrorHandlerMiddleware,
        debug=settings.DEBUG
    )
    
    # 2. Logging
    app.add_middleware(
        LoggingMiddleware,
        log_request_body=settings.DEBUG,
        log_response_body=False,
        exclude_paths=["/health", "/health/ready"]
    )
    
    # 3. Security Headers
    app.add_middleware(
        SecurityHeadersMiddleware,
        enable_hsts=not settings.DEBUG,
        enable_csp=True
    )
    
    # 4. Rate Limiting
    app.add_middleware(
        RateLimitMiddleware,
        requests_per_minute=settings.RATE_LIMIT_PER_MINUTE,
        requests_per_hour=settings.RATE_LIMIT_PER_HOUR,
        exclude_paths=["/health", "/docs", "/redoc", "/openapi.json"]
    )
    
    # 5. CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    )
    
    # 6. GZip compression
    app.add_middleware(
        GZipMiddleware,
        minimum_size=1000  # Only compress responses larger than 1KB
    )
    
    # 7. Trusted Host
    if not settings.DEBUG:
        # In production, only allow specific hosts
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*.secureauth.com", "secureauth.com"]  # Adjust as needed
        )
    
    # 8. Session middleware (for CSRF protection if needed)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        session_cookie="secureauth_session",
        max_age=settings.SESSION_TIMEOUT_MINUTES * 60,
        same_site="lax",
        https_only=not settings.DEBUG
    )

    # 9. CSRF Middleware
    app.add_middleware(
        CSRFMiddleware,
        secret=settings.SECRET_KEY,
        cookie_name="secureauth_csrf",
        cookie_secure=not settings.DEBUG,
        cookie_samesite="lax",
        header_name="X-CSRF-Token"
    )

    
    # Include routers
    app.include_router(
        health.router,
        prefix=settings.API_V1_STR,
        tags=["health"]
    )
    
    app.include_router(
        auth.router,
        prefix=settings.API_V1_STR,
        tags=["authentication"]
    )
    
    app.include_router(
        users.router,
        prefix=settings.API_V1_STR,
        tags=["users"]
    )
    
    # Root endpoint
    @app.get("/", include_in_schema=False)
    async def root() -> Dict[str, Any]:
        """Root endpoint."""
        return {
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "running",
            "docs": "/docs" if settings.DEBUG else None
        }
    
    # Custom exception handler
    @app.exception_handler(SecureAuthException)
    async def secure_auth_exception_handler(
        request: Request,
        exc: SecureAuthException
    ) -> JSONResponse:
        """Handle custom SecureAuth exceptions."""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "message": exc.message,
                    "type": type(exc).__name__,
                    "details": exc.details
                }
            }
        )
    
    return app


# Create application instance
app = create_application()


if __name__ == "__main__":
    import uvicorn
    
    # Run with uvicorn when executed directly
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True,
        workers=1 if settings.DEBUG else 4
    )