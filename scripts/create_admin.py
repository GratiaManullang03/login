#!/usr/bin/env python
"""
Script untuk membuat admin user di SecureAuth API.
Usage: python scripts/create_admin.py
"""

import asyncio
import sys
import getpass
from pathlib import Path
from typing import Optional

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import security
from app.db.session import SessionLocal, init_db
from app.models.user import User
from app.services.user import UserService
from app.services.audit import AuditService
from app.core.constants import AuditAction


async def get_user_input() -> dict:
    """Get admin user details from user input."""
    print("\n=== Create Admin User ===\n")
    
    # Get email
    while True:
        email = input("Admin email address: ").strip()
        if '@' in email and '.' in email:
            break
        print("Invalid email format. Please try again.")
    
    # Get username
    while True:
        username = input("Admin username: ").strip()
        if len(username) >= 3 and username.isalnum():
            break
        print("Username must be at least 3 characters and alphanumeric.")
    
    # Get password
    while True:
        password = getpass.getpass("Admin password: ")
        if len(password) < 8:
            print("Password must be at least 8 characters long.")
            continue
        
        # Validate password strength
        is_valid, errors = security.validate_password_strength(password)
        if not is_valid:
            print("\nPassword does not meet requirements:")
            for error in errors:
                print(f"  - {error}")
            print()
            continue
        
        # Confirm password
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            print("Passwords do not match. Please try again.")
            continue
        
        break
    
    # Additional details
    first_name = input("First name (optional): ").strip() or None
    last_name = input("Last name (optional): ").strip() or None
    
    return {
        "email": email.lower(),
        "username": username,
        "password": password,
        "first_name": first_name,
        "last_name": last_name
    }


async def create_admin_user(
    email: str,
    username: str,
    password: str,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None
) -> User:
    """
    Create admin user in database.
    
    Args:
        email: Admin email
        username: Admin username
        password: Admin password
        first_name: First name (optional)
        last_name: Last name (optional)
        
    Returns:
        Created admin user
    """
    async with SessionLocal() as db:
        user_service = UserService(db)
        audit_service = AuditService(db)
        
        # Check if admin already exists
        existing_user = await user_service.get_user_by_email(email)
        if existing_user:
            raise ValueError(f"User with email {email} already exists")
        
        existing_user = await user_service.get_user_by_username(username)
        if existing_user:
            raise ValueError(f"User with username {username} already exists")
        
        # Create metadata
        metadata = {
            "is_admin": True,
            "created_by": "create_admin_script"
        }
        
        if first_name:
            metadata["first_name"] = first_name
        if last_name:
            metadata["last_name"] = last_name
        
        # Create admin user
        admin_user = await user_service.create_user(
            email=email,
            username=username,
            password=password,
            metadata=metadata,
            ip_address="127.0.0.1",
            user_agent="create_admin_script"
        )
        
        # Mark as verified
        admin_user.u_is_verified = True
        admin_user.verify_email()
        
        # Add admin role/permissions (if implemented)
        # For now, we just use metadata flag
        
        await db.commit()
        
        # Audit admin creation
        await audit_service.log_action(
            action=AuditAction.ACCOUNT_CREATED,
            user_id=admin_user.u_id,
            entity_type="USER",
            entity_id=admin_user.u_id,
            metadata={
                "admin": True,
                "created_by_script": True
            }
        )
        
        return admin_user


async def main():
    """Main function."""
    try:
        # Initialize database
        print("Initializing database connection...")
        await init_db()
        
        # Check if running in interactive mode
        if len(sys.argv) > 1 and sys.argv[1] == "--non-interactive":
            # Non-interactive mode for automation
            if len(sys.argv) != 5:
                print("Usage: python create_admin.py --non-interactive <email> <username> <password>")
                sys.exit(1)
            
            user_data = {
                "email": sys.argv[2],
                "username": sys.argv[3],
                "password": sys.argv[4],
                "first_name": None,
                "last_name": None
            }
        else:
            # Interactive mode
            user_data = await get_user_input()
        
        # Create admin user
        print("\nCreating admin user...")
        admin_user = await create_admin_user(**user_data)
        
        print(f"\n✅ Admin user created successfully!")
        print(f"   Email: {admin_user.u_email}")
        print(f"   Username: {admin_user.u_username}")
        print(f"   ID: {admin_user.u_id}")
        print(f"   Verified: {admin_user.u_is_verified}")
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error creating admin user: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())