"""
Konfigurasi aplikasi menggunakan Pydantic Settings.
Semua konfigurasi dimuat dari environment variables atau file .env.
"""

from typing import Optional, List, Union
from datetime import timedelta
from functools import lru_cache

from pydantic import Field, field_validator, PostgresDsn, RedisDsn, AnyHttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Konfigurasi aplikasi utama."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )
    
    # Application Settings
    APP_NAME: str = Field(default="SecureAuth API", description="Nama aplikasi")
    APP_VERSION: str = Field(default="1.0.0", description="Versi aplikasi")
    DEBUG: bool = Field(default=False, description="Mode debug")
    ENVIRONMENT: str = Field(default="development", description="Environment aplikasi")
    API_V1_STR: str = Field(default="/api/v1", description="Prefix untuk API v1")
    
    # Security Settings
    SECRET_KEY: str = Field(..., description="Secret key untuk signing JWT dan enkripsi")
    ENCRYPTION_KEY: str = Field(..., description="Key untuk enkripsi data sensitif")
    CSRF_SECRET: Optional[str] = Field(None, description="Secret key khusus untuk proteksi CSRF")
    JWT_SECRET_KEY: Optional[str] = Field(None, description="Secret key khusus untuk JWT")
    DATABASE_ENCRYPTION_KEY: Optional[str] = Field(None, description="Key untuk enkripsi data database")
    SESSION_SECRET: Optional[str] = Field(None, description="Secret key untuk session")
    API_KEY_SALT: Optional[str] = Field(None, description="Salt untuk API key generation")
    PASSWORD_PEPPER: Optional[str] = Field(None, description="Pepper untuk password hashing")
    
    # JWT Settings
    ALGORITHM: str = Field(default="HS256", description="Algoritma untuk JWT")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, description="Masa berlaku access token dalam menit")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=30, description="Masa berlaku refresh token dalam hari")
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = Field(default=24, description="Masa berlaku token verifikasi email")
    PASSWORD_RESET_TOKEN_EXPIRE_HOURS: int = Field(default=1, description="Masa berlaku token reset password")
    
    # Password Policy
    PASSWORD_MIN_LENGTH: int = Field(default=8, description="Panjang minimal password")
    PASSWORD_REQUIRE_UPPERCASE: bool = Field(default=True, description="Memerlukan huruf besar")
    PASSWORD_REQUIRE_LOWERCASE: bool = Field(default=True, description="Memerlukan huruf kecil")
    PASSWORD_REQUIRE_NUMBERS: bool = Field(default=True, description="Memerlukan angka")
    PASSWORD_REQUIRE_SPECIAL: bool = Field(default=True, description="Memerlukan karakter khusus")
    PASSWORD_HISTORY_COUNT: int = Field(default=5, description="Jumlah password lama yang disimpan")
    
    # Account Security
    MAX_LOGIN_ATTEMPTS: int = Field(default=5, description="Maksimal percobaan login")
    ACCOUNT_LOCKOUT_MINUTES: int = Field(default=30, description="Durasi lockout akun dalam menit")
    SESSION_TIMEOUT_MINUTES: int = Field(default=1440, description="Timeout session dalam menit")
    REQUIRE_EMAIL_VERIFICATION: bool = Field(default=True, description="Memerlukan verifikasi email")
    
    # Two Factor Authentication
    TWO_FACTOR_ISSUER_NAME: str = Field(default="SecureAuth", description="Nama issuer untuk 2FA")
    TWO_FACTOR_BACKUP_CODES_COUNT: int = Field(default=10, description="Jumlah backup codes 2FA")
    
    # Device Tracking
    DEVICE_TRUST_DAYS: int = Field(default=30, description="Durasi trust device dalam hari")
    MAX_DEVICES_PER_USER: int = Field(default=10, description="Maksimal device per user")
    
    # Database
    DATABASE_URL: PostgresDsn = Field(..., description="PostgreSQL connection URL")
    DB_POOL_SIZE: int = Field(default=20, description="Database connection pool size")
    DB_MAX_OVERFLOW: int = Field(default=0, description="Database max overflow connections")
    DB_POOL_PRE_PING: bool = Field(default=True, description="Pre-ping database connections")
    
    # Redis
    REDIS_URL: RedisDsn = Field(..., description="Redis connection URL")
    REDIS_POOL_SIZE: int = Field(default=10, description="Redis connection pool size")
    
    # Email Settings
    SMTP_HOST: str = Field(default="localhost", description="SMTP server host")
    SMTP_PORT: int = Field(default=587, description="SMTP server port")
    SMTP_USER: Optional[str] = Field(None, description="SMTP username")
    SMTP_PASSWORD: Optional[str] = Field(None, description="SMTP password")
    SMTP_TLS: bool = Field(default=True, description="Enable SMTP TLS")
    SMTP_SSL: bool = Field(default=False, description="Enable SMTP SSL")
    EMAIL_FROM_NAME: str = Field(default="SecureAuth", description="Email sender name")
    EMAIL_FROM_ADDRESS: str = Field(default="noreply@example.com", description="Email sender address")
    
    # CORS Settings
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="Allowed CORS origins"
    )
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, description="Rate limit per menit")
    RATE_LIMIT_PER_HOUR: int = Field(default=1000, description="Rate limit per jam")
    LOGIN_RATE_LIMIT_PER_MINUTE: int = Field(default=5, description="Login rate limit per menit")
    
    # Logging
    LOG_LEVEL: str = Field(default="INFO", description="Log level")
    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format"
    )
    
    # Frontend URL
    FRONTEND_URL: AnyHttpUrl = Field(
        default="http://localhost:3000",
        description="Frontend URL untuk email links"
    )
    
    # Additional Security Settings
    USE_SECURE_COOKIES: bool = Field(default=True, description="Use secure cookies")
    ROTATE_REFRESH_TOKENS: bool = Field(default=True, description="Rotate refresh tokens on use")
    
    @field_validator("BACKEND_CORS_ORIGINS", mode='before')
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        """Parse CORS origins dari string atau list."""
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    @field_validator("DATABASE_URL", mode='before')
    def validate_postgres_url(cls, v: str) -> str:
        """Validate PostgreSQL URL."""
        if not v:
            raise ValueError("DATABASE_URL must be set")
        return v
    
    @field_validator("REDIS_URL", mode='before')
    def validate_redis_url(cls, v: str) -> str:
        """Validate Redis URL."""
        if not v:
            raise ValueError("REDIS_URL must be set")
        return v
    
    # Computed properties for backwards compatibility
    @property
    def access_token_expire_timedelta(self) -> timedelta:
        """Return timedelta untuk access token expiration."""
        return timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    @property
    def refresh_token_expire_timedelta(self) -> timedelta:
        """Return timedelta untuk refresh token expiration."""
        return timedelta(days=self.REFRESH_TOKEN_EXPIRE_DAYS)
    
    @property
    def email_verification_expire_timedelta(self) -> timedelta:
        """Return timedelta untuk email verification token expiration."""
        return timedelta(hours=self.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    
    @property
    def password_reset_expire_timedelta(self) -> timedelta:
        """Return timedelta untuk password reset token expiration."""
        return timedelta(hours=self.PASSWORD_RESET_TOKEN_EXPIRE_HOURS)
    
    @property
    def account_lockout_timedelta(self) -> timedelta:
        """Return timedelta untuk account lockout duration."""
        return timedelta(minutes=self.ACCOUNT_LOCKOUT_MINUTES)

@lru_cache()
def get_settings() -> Settings:
    """
    Mendapatkan cached settings instance.
    Menggunakan lru_cache untuk memastikan settings hanya di-load sekali.
    """
    return Settings()


# Global settings instance
settings = get_settings()