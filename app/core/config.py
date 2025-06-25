"""
Konfigurasi aplikasi menggunakan Pydantic Settings.
Semua konfigurasi dimuat dari environment variables atau file .env.
"""

from typing import Optional, List, Union
from datetime import timedelta
from functools import lru_cache

from pydantic import Field, validator, PostgresDsn, RedisDsn, AnyHttpUrl
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
    ENVIRONMENT: str = Field(default="production", description="Environment aplikasi")
    API_V1_STR: str = Field(default="/api/v1", description="Prefix untuk API v1")
    
    # Security Settings
    SECRET_KEY: str = Field(..., description="Secret key untuk signing JWT dan enkripsi")
    ENCRYPTION_KEY: str = Field(..., description="Key untuk enkripsi data sensitif")
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
    PASSWORD_HISTORY_COUNT: int = Field(default=5, description="Jumlah password lama yang tidak boleh digunakan kembali")
    
    # Account Security
    MAX_LOGIN_ATTEMPTS: int = Field(default=5, description="Maksimal percobaan login sebelum account dikunci")
    ACCOUNT_LOCKOUT_MINUTES: int = Field(default=30, description="Durasi penguncian account dalam menit")
    SESSION_TIMEOUT_MINUTES: int = Field(default=1440, description="Timeout sesi dalam menit (24 jam)")
    REQUIRE_EMAIL_VERIFICATION: bool = Field(default=True, description="Memerlukan verifikasi email")
    
    # Database
    DATABASE_URL: PostgresDsn = Field(..., description="PostgreSQL connection string")
    DB_POOL_SIZE: int = Field(default=20, description="Ukuran connection pool database")
    DB_MAX_OVERFLOW: int = Field(default=0, description="Maximum overflow connections")
    DB_POOL_PRE_PING: bool = Field(default=True, description="Test connections before using")
    
    # Redis
    REDIS_URL: RedisDsn = Field(..., description="Redis connection string untuk caching dan rate limiting")
    REDIS_POOL_SIZE: int = Field(default=10, description="Ukuran connection pool Redis")
    
    # Email Settings
    SMTP_HOST: str = Field(..., description="SMTP server host")
    SMTP_PORT: int = Field(default=587, description="SMTP server port")
    SMTP_USER: str = Field(..., description="SMTP username")
    SMTP_PASSWORD: str = Field(..., description="SMTP password")
    SMTP_TLS: bool = Field(default=True, description="Gunakan TLS")
    SMTP_SSL: bool = Field(default=False, description="Gunakan SSL")
    EMAIL_FROM_NAME: str = Field(default="SecureAuth", description="Nama pengirim email")
    EMAIL_FROM_ADDRESS: str = Field(..., description="Alamat email pengirim")
    
    # CORS Settings
    BACKEND_CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000"],
        description="List of allowed origins"
    )

    # Frontend URL (untuk email links)
    FRONTEND_URL: AnyHttpUrl = Field(..., description="URL Frontend untuk link email")
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, description="Request per menit per IP")
    RATE_LIMIT_PER_HOUR: int = Field(default=1000, description="Request per jam per IP")
    LOGIN_RATE_LIMIT_PER_MINUTE: int = Field(default=5, description="Login attempts per menit per IP")
    
    # Two Factor Authentication
    TWO_FACTOR_ISSUER_NAME: str = Field(default="SecureAuth", description="Nama issuer untuk 2FA")
    TWO_FACTOR_BACKUP_CODES_COUNT: int = Field(default=10, description="Jumlah backup codes yang digenerate")
    
    # Logging
    LOG_LEVEL: str = Field(default="INFO", description="Level logging")
    LOG_FORMAT: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Format log"
    )
    
    # Device Tracking
    DEVICE_TRUST_DAYS: int = Field(default=30, description="Berapa lama device dipercaya dalam hari")
    MAX_DEVICES_PER_USER: int = Field(default=10, description="Maksimal device per user")

    # Additional Security Settings
    USE_SECURE_COOKIES: bool = Field(default=True, description="Set cookie dengan flag Secure (hanya HTTPS)")
    ROTATE_REFRESH_TOKENS: bool = Field(default=True, description="Rotasi refresh token setelah digunakan")
    
    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        """Parse CORS origins dari string atau list."""
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    @validator("DATABASE_URL", pre=True)
    def validate_postgres_url(cls, v: str) -> str:
        """Validasi dan format PostgreSQL URL."""
        if not v:
            raise ValueError("DATABASE_URL is required")
        # Konversi postgresql:// ke postgresql+asyncpg:// untuk async support
        if v.startswith("postgresql://"):
            v = v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v
    
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
    
    class Config:
        """Pydantic config."""
        case_sensitive = False
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    """
    Mendapatkan cached settings instance.
    Menggunakan lru_cache untuk memastikan settings hanya di-load sekali.
    """
    return Settings()


# Global settings instance
settings = get_settings()