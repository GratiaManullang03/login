# SecureAuth API

A production-ready, secure authentication and identity management API built with FastAPI, featuring enterprise-grade security, scalability, and comprehensive user management capabilities.

## 🚀 Features

### Core Authentication
- **JWT-based Authentication** with access and refresh tokens
- **Email Verification** with secure token generation
- **Password Reset** functionality with time-limited tokens
- **Session Management** with device tracking and multi-session support

### Advanced Security
- **Two-Factor Authentication (2FA)** with TOTP support
- **Account Lockout Protection** after failed login attempts
- **Password Policy Enforcement** with strength validation
- **Password History** to prevent password reuse
- **Device Fingerprinting and Trust** management
- **Rate Limiting** per IP and per user
- **Audit Logging** for all security-relevant actions

### User Management
- **User Registration** with email verification
- **Profile Management** with metadata support
- **Device Management** with trusted device functionality
- **Session Management** with ability to revoke sessions

### Technical Features
- **Async/Await** throughout for high performance
- **Type Hints** for better code quality
- **Comprehensive Error Handling** with custom exceptions
- **Request/Response Validation** using Pydantic
- **Database Migrations** with Alembic
- **Redis Integration** for caching and rate limiting
- **Docker Support** for easy deployment
- **Comprehensive Test Suite** with pytest
- **API Documentation** with OpenAPI/Swagger

## 📋 Requirements

- Python 3.11+
- PostgreSQL 15+
- Redis 7+
- Docker & Docker Compose (optional)

## 🛠️ Installation

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/yourusername/secureauth-api.git
cd secureauth-api
```