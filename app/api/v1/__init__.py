"""
API v1 module.
Berisi semua endpoints untuk API versi 1.
"""

from app.api.v1.auth import router as auth_router
from app.api.v1.users import router as users_router
from app.api.v1.health import router as health_router

__all__ = ["auth_router", "users_router", "health_router"]