#!/usr/bin/env python3
"""
Quick test script untuk SecureAuth API.
Menguji basic functionality seperti health check, registration, dan login.
"""

import asyncio
import httpx
import json
from datetime import datetime
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from app.core.config import settings

# Base URL
BASE_URL = "http://localhost:8000"
API_V1_URL = f"{BASE_URL}{settings.API_V1_STR}"

# Test data
TEST_USER = {
    "email": f"test_{datetime.now().timestamp()}@example.com",
    "username": f"testuser_{int(datetime.now().timestamp())}",
    "password": "TestPassword123!",
    "full_name": "Test User"
}


async def test_health_check():
    """Test health check endpoints."""
    print("\n🏥 Testing Health Check Endpoints...")
    
    async with httpx.AsyncClient() as client:
        # Basic health
        response = await client.get(f"{API_V1_URL}/health")
        print(f"  ✓ GET /health: {response.status_code}")
        if response.status_code == 200:
            print(f"    Response: {response.json()}")
        
        # Readiness check
        response = await client.get(f"{API_V1_URL}/health/ready")
        print(f"  ✓ GET /health/ready: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"    Database: {data['checks']['database']}")
            print(f"    Redis: {data['checks']['redis']}")


async def test_user_registration():
    """Test user registration."""
    print("\n👤 Testing User Registration...")
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{API_V1_URL}/users/register",
            json=TEST_USER
        )
        
        print(f"  ✓ POST /users/register: {response.status_code}")
        
        if response.status_code == 201:
            data = response.json()
            print(f"    User ID: {data['user']['id']}")
            print(f"    Email: {data['user']['email']}")
            print(f"    Message: {data['message']}")
            return data['user']
        else:
            print(f"    Error: {response.json()}")
            return None


async def test_user_login():
    """Test user login."""
    print("\n🔐 Testing User Login...")
    
    async with httpx.AsyncClient() as client:
        # Login with form data
        response = await client.post(
            f"{API_V1_URL}/auth/login",
            data={
                "username": TEST_USER["email"],  # Can use email or username
                "password": TEST_USER["password"]
            }
        )
        
        print(f"  ✓ POST /auth/login: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"    Access Token: {data['access_token'][:50]}...")
            print(f"    Token Type: {data['token_type']}")
            print(f"    User ID: {data['user']['id']}")
            return data['access_token']
        else:
            print(f"    Error: {response.json()}")
            return None


async def test_get_profile(access_token: str):
    """Test get user profile."""
    print("\n📋 Testing Get User Profile...")
    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{API_V1_URL}/users/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        print(f"  ✓ GET /users/me: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"    Email: {data['email']}")
            print(f"    Username: {data['username']}")
            print(f"    Verified: {data['is_verified']}")
        else:
            print(f"    Error: {response.json()}")


async def test_csrf_token():
    """Test CSRF token endpoint."""
    print("\n🛡️ Testing CSRF Token...")
    
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{API_V1_URL}/auth/csrf-token")
        
        print(f"  ✓ GET /auth/csrf-token: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"    CSRF Token: {data.get('csrf_token', 'Not generated yet')}")


async def test_api_flow():
    """Test complete API flow."""
    print("🚀 Starting SecureAuth API Tests")
    print("=" * 50)
    
    try:
        # 1. Health check
        await test_health_check()
        
        # 2. CSRF token
        await test_csrf_token()
        
        # 3. Register user
        user = await test_user_registration()
        
        if user:
            # 4. Login
            access_token = await test_user_login()
            
            if access_token:
                # 5. Get profile
                await test_get_profile(access_token)
        
        print("\n✅ All tests completed!")
        
    except httpx.ConnectError:
        print("\n❌ Error: Cannot connect to API. Is the server running?")
        print("   Run: uvicorn app.main:app --reload")
    except Exception as e:
        print(f"\n❌ Error: {e}")


async def test_email_verification(user_email: str):
    """Test email verification flow."""
    print("\n📧 Testing Email Verification...")
    
    # Note: In real scenario, you would get the token from email
    print("  ℹ️  Check your email for verification link")
    print(f"     Email sent to: {user_email}")
    
    if settings.SMTP_HOST == "mailhog":
        print(f"     View emails at: http://localhost:8025")


def main():
    """Main function."""
    print(f"🌐 API Base URL: {API_V1_URL}")
    print(f"📚 API Docs: {BASE_URL}/docs")
    print(f"📖 ReDoc: {BASE_URL}/redoc")
    
    # Run tests
    asyncio.run(test_api_flow())
    
    print("\n💡 Tips:")
    print("  - Check Swagger UI for interactive API testing")
    print("  - Use Mailhog UI to view sent emails")
    print("  - Check logs for detailed error messages")


if __name__ == "__main__":
    main()