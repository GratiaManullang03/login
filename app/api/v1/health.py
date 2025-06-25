"""
Health check endpoints untuk API v1.
Menyediakan status aplikasi dan dependency checks.
"""

from datetime import datetime, timezone
from typing import Dict, Any

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import redis.asyncio as redis

from app.api.dependencies.database import get_db
from app.core.config import settings
from app.schemas.response import HealthCheckResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/", response_model=HealthCheckResponse)
async def health_check() -> HealthCheckResponse:
    """
    Basic health check endpoint.
    
    Returns:
        Basic health status
    """
    return HealthCheckResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        version=settings.APP_VERSION,
        service=settings.APP_NAME
    )


@router.get("/ready", response_model=Dict[str, Any])
async def readiness_check(
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """
    Readiness check dengan dependency validation.
    Checks database dan Redis connectivity.
    
    Args:
        db: Database session
        
    Returns:
        Detailed readiness status
    """
    checks = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": settings.APP_VERSION,
        "checks": {
            "database": False,
            "redis": False
        },
        "details": {}
    }
    
    # Check database
    try:
        result = await db.execute(text("SELECT 1"))
        await db.commit()
        checks["checks"]["database"] = True
        checks["details"]["database"] = "Connected"
    except Exception as e:
        checks["status"] = "unhealthy"
        checks["details"]["database"] = f"Error: {str(e)}"
    
    # Check Redis
    try:
        redis_client = redis.from_url(
            str(settings.REDIS_URL),
            encoding="utf-8",
            decode_responses=True
        )
        await redis_client.ping()
        await redis_client.close()
        checks["checks"]["redis"] = True
        checks["details"]["redis"] = "Connected"
    except Exception as e:
        checks["status"] = "unhealthy"
        checks["details"]["redis"] = f"Error: {str(e)}"
    
    # Overall status
    if not all(checks["checks"].values()):
        checks["status"] = "unhealthy"
    
    return checks


@router.get("/live", status_code=status.HTTP_204_NO_CONTENT)
async def liveness_check() -> None:
    """
    Liveness check untuk Kubernetes.
    Simple endpoint yang return 204 jika service alive.
    """
    # Jika endpoint ini responding, service is alive
    return None