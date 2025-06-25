#!/usr/bin/env python
"""
Script untuk inisialisasi database SecureAuth API.
Membuat semua tabel dan menjalankan migrasi yang diperlukan.
Usage: python scripts/init_db.py
"""

import asyncio
import sys
from pathlib import Path
import logging

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from sqlalchemy import text
from alembic import command
from alembic.config import Config

from app.core.config import settings
from app.db.session import engine, SessionLocal
from app.db.base import Base

# Import all models to ensure they're registered
from app.models import (
    user,
    session,
    token,
    audit,
    device,
    two_factor,
    password_history,
    login_attempt
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def create_database():
    """Create database if it doesn't exist."""
    # Extract database name from URL
    db_url = str(settings.DATABASE_URL)
    db_name = db_url.split('/')[-1].split('?')[0]
    
    # Connect to default postgres database to create our database
    default_db_url = db_url.replace(f'/{db_name}', '/postgres')
    
    # Use sync engine for database creation
    from sqlalchemy import create_engine
    temp_engine = create_engine(default_db_url.replace('+asyncpg', ''))
    
    try:
        with temp_engine.connect() as conn:
            # Check if database exists
            result = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :dbname"),
                {"dbname": db_name}
            )
            exists = result.scalar()
            
            if not exists:
                # Create database
                conn.execute(text("COMMIT"))  # Exit transaction
                conn.execute(text(f"CREATE DATABASE {db_name}"))
                logger.info(f"Created database: {db_name}")
            else:
                logger.info(f"Database already exists: {db_name}")
                
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        raise
    finally:
        temp_engine.dispose()


async def create_extensions():
    """Create required PostgreSQL extensions."""
    async with SessionLocal() as session:
        try:
            # Create uuid-ossp extension
            await session.execute(text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'))
            logger.info("Created uuid-ossp extension")
            
            # Create other useful extensions
            await session.execute(text('CREATE EXTENSION IF NOT EXISTS "pgcrypto"'))
            logger.info("Created pgcrypto extension")
            
            await session.commit()
        except Exception as e:
            logger.error(f"Error creating extensions: {e}")
            await session.rollback()
            raise


async def create_tables():
    """Create all tables from SQLAlchemy models."""
    try:
        async with engine.begin() as conn:
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Created all database tables")
    except Exception as e:
        logger.error(f"Error creating tables: {e}")
        raise


async def verify_tables():
    """Verify that all required tables exist."""
    required_tables = [
        'users',
        'user_sessions',
        'password_history',
        'login_attempts',
        'user_tokens',
        'audit_logs',
        'user_devices',
        'two_factor_auth'
    ]
    
    async with SessionLocal() as session:
        # Check if tables exist
        result = await session.execute(
            text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_type = 'BASE TABLE'
            """)
        )
        existing_tables = {row[0] for row in result}
        
        missing_tables = set(required_tables) - existing_tables
        
        if missing_tables:
            logger.warning(f"Missing tables: {missing_tables}")
            return False
        
        logger.info("All required tables exist")
        return True


async def create_indexes():
    """Create additional indexes for performance."""
    indexes = [
        # User indexes
        "CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users(LOWER(u_email))",
        "CREATE INDEX IF NOT EXISTS idx_users_username_lower ON users(LOWER(u_username))",
        "CREATE INDEX IF NOT EXISTS idx_users_is_active_verified ON users(u_is_active, u_is_verified)",
        
        # Session indexes
        "CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(us_expires_at)",
        "CREATE INDEX IF NOT EXISTS idx_user_sessions_last_activity ON user_sessions(us_last_activity)",
        
        # Login attempt indexes
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_address ON login_attempts(la_ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_attempted_at ON login_attempts(la_attempted_at)",
        
        # Audit log indexes
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(al_action)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(al_created_at)",
        
        # Token indexes
        "CREATE INDEX IF NOT EXISTS idx_user_tokens_type_expires ON user_tokens(ut_token_type, ut_expires_at)",
        
        # Device indexes
        "CREATE INDEX IF NOT EXISTS idx_user_devices_device_id ON user_devices(ud_device_id)",
        "CREATE INDEX IF NOT EXISTS idx_user_devices_last_used ON user_devices(ud_last_used_at)",
    ]
    
    async with SessionLocal() as session:
        for index_sql in indexes:
            try:
                await session.execute(text(index_sql))
                logger.info(f"Created index: {index_sql.split('idx_')[1].split(' ')[0]}")
            except Exception as e:
                logger.warning(f"Error creating index: {e}")
        
        await session.commit()


async def run_alembic_migrations():
    """Run Alembic migrations."""
    try:
        # Get Alembic configuration
        alembic_cfg = Config("alembic.ini")
        
        # Run migrations
        command.upgrade(alembic_cfg, "head")
        logger.info("Alembic migrations completed")
    except Exception as e:
        logger.warning(f"Alembic migrations skipped or failed: {e}")
        # This is not critical if tables are created directly


async def create_initial_data():
    """Create any initial data required."""
    async with SessionLocal() as session:
        # Example: Create default audit log entry
        from app.models.audit import AuditLog
        from app.core.constants import AuditAction
        
        # Check if any data exists
        result = await session.execute(
            text("SELECT COUNT(*) FROM audit_logs")
        )
        count = result.scalar()
        
        if count == 0:
            # Create initial audit log
            initial_log = AuditLog(
                al_action=AuditAction.SYSTEM_INITIALIZED,
                al_metadata={"message": "Database initialized"}
            )
            session.add(initial_log)
            await session.commit()
            logger.info("Created initial audit log entry")


async def main():
    """Main initialization function."""
    logger.info("=== SecureAuth API Database Initialization ===\n")
    
    try:
        # Step 1: Create database
        logger.info("Step 1: Creating database...")
        await create_database()
        
        # Step 2: Create extensions
        logger.info("\nStep 2: Creating PostgreSQL extensions...")
        await create_extensions()
        
        # Step 3: Create tables
        logger.info("\nStep 3: Creating database tables...")
        await create_tables()
        
        # Step 4: Verify tables
        logger.info("\nStep 4: Verifying tables...")
        tables_ok = await verify_tables()
        if not tables_ok:
            raise Exception("Table verification failed")
        
        # Step 5: Create indexes
        logger.info("\nStep 5: Creating performance indexes...")
        await create_indexes()
        
        # Step 6: Run Alembic migrations (if any)
        logger.info("\nStep 6: Running Alembic migrations...")
        await run_alembic_migrations()
        
        # Step 7: Create initial data
        logger.info("\nStep 7: Creating initial data...")
        await create_initial_data()
        
        logger.info("\n✅ Database initialization completed successfully!")
        logger.info("\nNext steps:")
        logger.info("1. Run 'python scripts/create_admin.py' to create an admin user")
        logger.info("2. Start the API with 'uvicorn app.main:app --reload'")
        
    except Exception as e:
        logger.error(f"\n❌ Database initialization failed: {e}")
        sys.exit(1)
    finally:
        # Close engine
        await engine.dispose()


if __name__ == "__main__":
    # Check if database URL is configured
    if not settings.DATABASE_URL:
        logger.error("DATABASE_URL not configured. Please set it in .env file")
        sys.exit(1)
    
    # Run initialization
    asyncio.run(main())