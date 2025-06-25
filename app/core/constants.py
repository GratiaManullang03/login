"""
Konstanta yang digunakan di seluruh aplikasi SecureAuth API.
"""

from enum import Enum


class TokenType(str, Enum):
    """Tipe-tipe token yang digunakan dalam sistem."""
    EMAIL_VERIFICATION = "EMAIL_VERIFICATION"
    PASSWORD_RESET = "PASSWORD_RESET"
    TWO_FACTOR_AUTH = "TWO_FACTOR_AUTH"
    API_KEY = "API_KEY"


class AuditAction(str, Enum):
    """Aksi-aksi yang di-log dalam audit trail."""
    # Authentication actions
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    TOKEN_REFRESH = "TOKEN_REFRESH"
    
    # Account actions
    ACCOUNT_CREATED = "ACCOUNT_CREATED"
    ACCOUNT_VERIFIED = "ACCOUNT_VERIFIED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
    ACCOUNT_DELETED = "ACCOUNT_DELETED"
    
    # Password actions
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED"
    PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED"
    
    # Profile actions
    PROFILE_UPDATED = "PROFILE_UPDATED"
    EMAIL_CHANGED = "EMAIL_CHANGED"
    
    # Security actions
    TWO_FACTOR_ENABLED = "TWO_FACTOR_ENABLED"
    TWO_FACTOR_DISABLED = "TWO_FACTOR_DISABLED"
    TWO_FACTOR_VERIFIED = "TWO_FACTOR_VERIFIED"
    TWO_FACTOR_FAILED = "TWO_FACTOR_FAILED"
    
    # Device actions
    DEVICE_ADDED = "DEVICE_ADDED"
    DEVICE_REMOVED = "DEVICE_REMOVED"
    DEVICE_TRUSTED = "DEVICE_TRUSTED"
    
    # Session actions
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_TERMINATED = "SESSION_TERMINATED"
    ALL_SESSIONS_TERMINATED = "ALL_SESSIONS_TERMINATED"


class LogoutReason(str, Enum):
    """Alasan logout."""
    USER_INITIATED = "USER_INITIATED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    ADMIN_TERMINATED = "ADMIN_TERMINATED"
    SECURITY_POLICY = "SECURITY_POLICY"


class LoginFailureReason(str, Enum):
    """Alasan kegagalan login."""
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_NOT_VERIFIED = "ACCOUNT_NOT_VERIFIED"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED"
    TWO_FACTOR_FAILED = "TWO_FACTOR_FAILED"
    RATE_LIMITED = "RATE_LIMITED"


class DeviceType(str, Enum):
    """Tipe-tipe device."""
    MOBILE = "MOBILE"
    DESKTOP = "DESKTOP"
    TABLET = "TABLET"
    UNKNOWN = "UNKNOWN"


class Platform(str, Enum):
    """Platform device."""
    IOS = "IOS"
    ANDROID = "ANDROID"
    WINDOWS = "WINDOWS"
    MACOS = "MACOS"
    LINUX = "LINUX"
    WEB = "WEB"
    UNKNOWN = "UNKNOWN"


class TwoFactorMethod(str, Enum):
    """Metode two-factor authentication."""
    TOTP = "TOTP"  # Time-based One-Time Password
    SMS = "SMS"
    EMAIL = "EMAIL"
    BACKUP_CODE = "BACKUP_CODE"


class EntityType(str, Enum):
    """Tipe entity untuk audit logging."""
    USER = "USER"
    SESSION = "SESSION"
    TOKEN = "TOKEN"
    DEVICE = "DEVICE"
    SETTINGS = "SETTINGS"


# Response Messages
class ResponseMessage:
    """Pesan response standar."""
    # Success messages
    LOGIN_SUCCESS = "Login successful"
    LOGOUT_SUCCESS = "Logout successful"
    REGISTER_SUCCESS = "Registration successful. Please check your email to verify your account."
    EMAIL_VERIFIED = "Email verified successfully"
    PASSWORD_RESET_REQUESTED = "Password reset instructions sent to your email"
    PASSWORD_RESET_SUCCESS = "Password reset successful"
    PASSWORD_CHANGED = "Password changed successfully"
    
    # Error messages
    INVALID_CREDENTIALS = "Invalid email or password"
    ACCOUNT_LOCKED = "Account is locked due to multiple failed login attempts"
    EMAIL_NOT_VERIFIED = "Please verify your email before logging in"
    TOKEN_EXPIRED = "Token has expired"
    TOKEN_INVALID = "Invalid token"
    USER_NOT_FOUND = "User not found"
    EMAIL_ALREADY_EXISTS = "Email already registered"
    USERNAME_ALREADY_EXISTS = "Username already taken"
    
    # 2FA messages
    TWO_FACTOR_REQUIRED = "Two-factor authentication required"
    TWO_FACTOR_INVALID = "Invalid two-factor code"
    TWO_FACTOR_ENABLED = "Two-factor authentication enabled"
    TWO_FACTOR_DISABLED = "Two-factor authentication disabled"


# Regex Patterns
class RegexPattern:
    """Regex patterns untuk validasi."""
    EMAIL = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    USERNAME = r'^[a-zA-Z0-9_-]{3,50}$'
    STRONG_PASSWORD = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    PHONE = r'^\+?1?\d{9,15}$'
    UUID = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'


# Cache Keys
class CacheKey:
    """Template untuk cache keys."""
    USER_BY_ID = "user:id:{user_id}"
    USER_BY_EMAIL = "user:email:{email}"
    USER_SESSIONS = "user:sessions:{user_id}"
    RATE_LIMIT_LOGIN = "rate_limit:login:{ip}"
    RATE_LIMIT_API = "rate_limit:api:{ip}"
    EMAIL_VERIFICATION = "email:verification:{token}"
    PASSWORD_RESET = "password:reset:{token}"
    TWO_FACTOR_SESSION = "2fa:session:{session_id}"


# Default Values
class DefaultValue:
    """Nilai default untuk berbagai setting."""
    PAGINATION_PAGE_SIZE = 20
    MAX_PAGINATION_SIZE = 100
    SESSION_COOKIE_NAME = "session_token"
    CSRF_COOKIE_NAME = "csrf_token"
    DEVICE_FINGERPRINT_COOKIE = "device_fp"