"""
Audit service untuk SecureAuth API.
Menangani audit logging untuk compliance dan security monitoring.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple 
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from sqlalchemy.orm import selectinload
from sqlalchemy.sql import text

from app.core.constants import AuditAction, EntityType
from app.models.audit import AuditLog


class AuditService:
    """
    Service class untuk audit logging operations.
    Mencatat semua perubahan penting untuk audit trail.
    """
    
    def __init__(self, db: AsyncSession):
        """
        Initialize audit service.
        
        Args:
            db: Database session
        """
        self.db = db
    
    async def log_action(
        self,
        action: AuditAction,
        user_id: Optional[UUID] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[UUID] = None,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        """
        Log audit action.
        
        Args:
            action: Action yang dilakukan
            user_id: User yang melakukan action
            entity_type: Type of entity yang diubah
            entity_id: ID of entity yang diubah
            old_values: Nilai lama (untuk update)
            new_values: Nilai baru (untuk update)
            ip_address: IP address
            user_agent: User agent
            metadata: Additional metadata
            
        Returns:
            Created audit log entry
        """
        # Create audit log entry
        audit_log = AuditLog(
            al_user_id=user_id,
            al_action=action,
            al_entity_type=entity_type,
            al_entity_id=entity_id,
            al_old_values=old_values,
            al_new_values=new_values,
            al_ip_address=ip_address,
            al_user_agent=user_agent,
            al_metadata=metadata
        )
        
        self.db.add(audit_log)
        
        # Commit immediately untuk audit logs
        # Audit logs harus persisted bahkan jika main transaction rollback
        await self.db.commit()
        
        return audit_log
    
    async def get_audit_logs(
        self,
        user_id: Optional[UUID] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[UUID] = None,
        action: Optional[AuditAction] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        ip_address: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
        order_desc: bool = True
    ) -> Tuple[List[AuditLog], int]:
        """
        Get audit logs dengan filtering dan pagination.
        
        Args:
            user_id: Filter by user ID
            entity_type: Filter by entity type
            entity_id: Filter by entity ID
            action: Filter by action
            start_date: Filter by start date
            end_date: Filter by end date
            ip_address: Filter by IP address
            page: Page number
            per_page: Items per page
            order_desc: Order by created_at descending
            
        Returns:
            Tuple of (audit_logs, total_count)
        """
        # Build base query
        query = select(AuditLog)
        count_query = select(func.count(AuditLog.al_id))
        
        # Apply filters
        filters = []
        
        if user_id:
            filters.append(AuditLog.al_user_id == user_id)
        
        if entity_type:
            filters.append(AuditLog.al_entity_type == entity_type)
        
        if entity_id:
            filters.append(AuditLog.al_entity_id == entity_id)
        
        if action:
            filters.append(AuditLog.al_action == action)
        
        if start_date:
            filters.append(AuditLog.created_at >= start_date)
        
        if end_date:
            filters.append(AuditLog.created_at <= end_date)
        
        if ip_address:
            filters.append(AuditLog.al_ip_address == ip_address)
        
        if filters:
            query = query.where(and_(*filters))
            count_query = count_query.where(and_(*filters))
        
        # Get total count
        total_result = await self.db.execute(count_query)
        total_count = total_result.scalar()
        
        # Apply ordering
        if order_desc:
            query = query.order_by(AuditLog.created_at.desc())
        else:
            query = query.order_by(AuditLog.created_at.asc())
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.limit(per_page).offset(offset)
        
        # Include user relationship
        query = query.options(selectinload(AuditLog.user))
        
        # Execute query
        result = await self.db.execute(query)
        audit_logs = result.scalars().all()
        
        return audit_logs, total_count
    
    async def get_user_activity_summary(
        self,
        user_id: UUID,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get user activity summary untuk specified period.
        
        Args:
            user_id: User ID
            days: Number of days to look back
            
        Returns:
            Activity summary dictionary
        """
        # Calculate date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        # Get action counts
        result = await self.db.execute(
            select(
                AuditLog.al_action,
                func.count(AuditLog.al_id).label("count")
            )
            .where(
                and_(
                    AuditLog.al_user_id == user_id,
                    AuditLog.created_at >= start_date
                )
            )
            .group_by(AuditLog.al_action)
        )
        
        action_counts = {row.al_action: row.count for row in result}
        
        # Get daily activity
        daily_result = await self.db.execute(
            text("""
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as count
                FROM audit_logs
                WHERE al_user_id = :user_id
                    AND created_at >= :start_date
                GROUP BY DATE(created_at)
                ORDER BY date DESC
            """),
            {"user_id": str(user_id), "start_date": start_date}
        )
        
        daily_activity = [
            {"date": row.date.isoformat(), "count": row.count}
            for row in daily_result
        ]
        
        # Get recent actions
        recent_logs, _ = await self.get_audit_logs(
            user_id=user_id,
            start_date=start_date,
            page=1,
            per_page=10
        )
        
        return {
            "user_id": user_id,
            "period_days": days,
            "total_actions": sum(action_counts.values()),
            "action_counts": action_counts,
            "daily_activity": daily_activity,
            "recent_actions": [log.to_dict() for log in recent_logs]
        }
    
    async def get_security_events(
        self,
        user_id: Optional[UUID] = None,
        hours: int = 24
    ) -> List[AuditLog]:
        """
        Get security-related events untuk monitoring.
        
        Args:
            user_id: Optional filter by user
            hours: Hours to look back
            
        Returns:
            List of security events
        """
        # Security-related actions
        security_actions = [
            AuditAction.LOGIN_FAILED,
            AuditAction.ACCOUNT_LOCKED,
            AuditAction.PASSWORD_CHANGED,
            AuditAction.PASSWORD_RESET_COMPLETED,
            AuditAction.TWO_FACTOR_FAILED,
            AuditAction.DEVICE_ADDED,
            AuditAction.ALL_SESSIONS_TERMINATED
        ]
        
        # Calculate time range
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        # Build query
        query = select(AuditLog).where(
            and_(
                AuditLog.al_action.in_(security_actions),
                AuditLog.created_at >= start_time
            )
        )
        
        if user_id:
            query = query.where(AuditLog.al_user_id == user_id)
        
        query = query.order_by(AuditLog.created_at.desc())
        query = query.options(selectinload(AuditLog.user))
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def get_failed_login_attempts(
        self,
        ip_address: Optional[str] = None,
        hours: int = 1
    ) -> int:
        """
        Get count of failed login attempts dari IP address.
        
        Args:
            ip_address: IP address to check
            hours: Hours to look back
            
        Returns:
            Count of failed attempts
        """
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        query = select(func.count(AuditLog.al_id)).where(
            and_(
                AuditLog.al_action == AuditAction.LOGIN_FAILED,
                AuditLog.created_at >= start_time
            )
        )
        
        if ip_address:
            query = query.where(AuditLog.al_ip_address == ip_address)
        
        result = await self.db.execute(query)
        return result.scalar() or 0
    
    async def cleanup_old_logs(self, retention_days: int = 365) -> int:
        """
        Cleanup old audit logs.
        
        Args:
            retention_days: Days to retain logs
            
        Returns:
            Number of logs deleted
        """
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        # Delete old logs
        result = await self.db.execute(
            text("""
                DELETE FROM audit_logs
                WHERE created_at < :cutoff_date
            """),
            {"cutoff_date": cutoff_date}
        )
        
        deleted_count = result.rowcount
        
        if deleted_count > 0:
            await self.db.commit()
            
            # Log the cleanup action
            await self.log_action(
                action=AuditAction.AUDIT_LOGS_CLEANED,
                metadata={
                    "deleted_count": deleted_count,
                    "retention_days": retention_days,
                    "cutoff_date": cutoff_date.isoformat()
                }
            )
        
        return deleted_count
    
    async def export_audit_logs(
        self,
        user_id: Optional[UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        format: str = "json"
    ) -> str:
        """
        Export audit logs untuk compliance/reporting.
        
        Args:
            user_id: Optional filter by user
            start_date: Start date
            end_date: End date
            format: Export format (json, csv)
            
        Returns:
            Exported data as string
        """
        # Get logs
        logs, _ = await self.get_audit_logs(
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            per_page=10000  # Large limit for export
        )
        
        if format == "json":
            import json
            return json.dumps(
                [log.to_dict(include_user=True) for log in logs],
                indent=2,
                default=str
            )
        elif format == "csv":
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(
                output,
                fieldnames=[
                    "al_id", "created_at", "al_user_id", "username",
                    "al_action", "al_entity_type", "al_entity_id",
                    "al_ip_address", "al_user_agent"
                ]
            )
            writer.writeheader()
            
            for log in logs:
                writer.writerow({
                    "al_id": str(log.al_id),
                    "created_at": log.created_at.isoformat(),
                    "al_user_id": str(log.al_user_id) if log.al_user_id else "",
                    "username": log.username or "",
                    "al_action": log.al_action,
                    "al_entity_type": log.al_entity_type or "",
                    "al_entity_id": str(log.al_entity_id) if log.al_entity_id else "",
                    "al_ip_address": log.al_ip_address or "",
                    "al_user_agent": log.al_user_agent or ""
                })
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported format: {format}")