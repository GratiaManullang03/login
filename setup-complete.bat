@echo off
echo ========================================
echo   COMPLETE DOCKER SETUP FOR AUTH-API
echo ========================================

:: 1. Clean Docker
echo [1/10] Cleaning Docker...
docker-compose down -v
docker system prune -f --volumes

:: 2. Create folders
echo [2/10] Creating folder structure...
mkdir app 2>nul
mkdir alembic\versions 2>nul
mkdir nginx\ssl 2>nul
mkdir scripts 2>nul
mkdir logs 2>nul

:: 3. Create nginx.conf
echo [3/10] Creating nginx.conf...
(
echo worker_processes 1;
echo.
echo events {
echo     worker_connections 1024;
echo }
echo.
echo http {
echo     upstream api {
echo         server api:8000;
echo     }
echo.
echo     server {
echo         listen 80;
echo         server_name localhost;
echo.
echo         location / {
echo             proxy_pass http://api;
echo             proxy_set_header Host $host;
echo             proxy_set_header X-Real-IP $remote_addr;
echo             proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
echo             proxy_set_header X-Forwarded-Proto $scheme;
echo         }
echo.
echo         location /api {
echo             proxy_pass http://api;
echo             proxy_set_header Host $host;
echo             proxy_set_header X-Real-IP $remote_addr;
echo         }
echo     }
echo }
) > nginx\nginx.conf

:: 4. Create main.py if not exists
if not exist "app\main.py" (
    echo [4/10] Creating app/main.py...
    (
    echo from fastapi import FastAPI
    echo from fastapi.middleware.cors import CORSMiddleware
    echo import os
    echo.
    echo app = FastAPI^(title="SecureAuth API", version="1.0.0"^)
    echo.
    echo # CORS
    echo origins = os.getenv^("BACKEND_CORS_ORIGINS", "http://localhost:3000,http://localhost:8000"^).split^(","^)
    echo app.add_middleware^(
    echo     CORSMiddleware,
    echo     allow_origins=origins,
    echo     allow_credentials=True,
    echo     allow_methods=["*"],
    echo     allow_headers=["*"],
    echo ^)
    echo.
    echo @app.get^("/api/v1/health"^)
    echo async def health_check^(^):
    echo     return {"status": "healthy", "service": "auth-api", "version": "1.0.0"}
    echo.
    echo @app.get^("/"^)
    echo async def root^(^):
    echo     return {"message": "SecureAuth API v1.0", "docs": "/docs"}
    ) > app\main.py
) else (
    echo [4/10] app/main.py already exists, skipping...
)

:: 5. Create alembic files
echo [5/10] Creating alembic files...
if not exist "alembic.ini" (
    (
    echo [alembic]
    echo script_location = alembic
    echo prepend_sys_path = .
    echo sqlalchemy.url = postgresql://secureauth:secureauth_password@postgres:5432/secureauth_db
    echo.
    echo [loggers]
    echo keys = root,sqlalchemy,alembic
    echo.
    echo [handlers]
    echo keys = console
    echo.
    echo [formatters]
    echo keys = generic
    echo.
    echo [logger_root]
    echo level = WARN
    echo handlers = console
    echo qualname =
    echo.
    echo [logger_sqlalchemy]
    echo level = WARN
    echo handlers =
    echo qualname = sqlalchemy.engine
    echo.
    echo [logger_alembic]
    echo level = INFO
    echo handlers =
    echo qualname = alembic
    echo.
    echo [handler_console]
    echo class = StreamHandler
    echo args = ^(sys.stderr,^)
    echo level = NOTSET
    echo formatter = generic
    echo.
    echo [formatter_generic]
    echo format = %%(levelname^)-5.5s [%%(name^)s] %%(message^)s
    echo datefmt = %%H:%%M:%%S
    ) > alembic.ini
)

:: 6. Pull latest images
echo [6/10] Pulling latest Docker images...
docker pull postgres:15-alpine
docker pull redis:7-alpine
docker pull nginx:alpine
docker pull mailhog/mailhog

:: 7. Build API image
echo [7/10] Building API image...
docker-compose build --no-cache api

:: 8. Start PostgreSQL first
echo [8/10] Starting PostgreSQL...
docker-compose up -d postgres

echo Waiting for PostgreSQL to initialize (20 seconds)...
timeout /t 20 /nobreak >nul

:: 9. Start all services
echo [9/10] Starting all services...
docker-compose up -d

echo Waiting for services to be ready (15 seconds)...
timeout /t 15 /nobreak >nul

:: 10. Show status
echo [10/10] Checking status...
echo.
docker-compose ps

:: Health check
echo.
echo Testing API health...
curl -s http://localhost:8000/api/v1/health

echo.
echo ========================================
echo   SETUP COMPLETE!
echo ========================================
echo.
echo Services:
echo - API: http://localhost:8000
echo - API Docs: http://localhost:8000/docs
echo - MailHog: http://localhost:8025
echo - PostgreSQL: localhost:5432
echo - Redis: localhost:6379
echo.
echo Commands:
echo - View logs: docker-compose logs -f
echo - Stop all: docker-compose down
echo - Restart: docker-compose restart
echo.

pause