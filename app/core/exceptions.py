"""
Custom exceptions untuk SecureAuth API.
Semua custom exceptions harus inherit dari base exceptions ini.
"""

from typing import Optional, Dict, Any


class SecureAuthException(Exception):
    """Base exception untuk semua custom exceptions di SecureAuth API."""
    
    def __init__(
        self,
        message: str,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize exception.
        
        Args:
            message: Error message
            status_code: HTTP status code
            details: Additional error details
        """
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class AuthenticationError(SecureAuthException):
    """Exception untuk error autentikasi."""
    
    def __init__(self, message: str = "Authentication failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=401, details=details)


class AuthorizationError(SecureAuthException):
    """Exception untuk error otorisasi."""
    
    def __init__(self, message: str = "Permission denied", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=403, details=details)


class ValidationError(SecureAuthException):
    """Exception untuk error validasi data."""
    
    def __init__(self, message: str = "Validation failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=422, details=details)


class NotFoundError(SecureAuthException):
    """Exception untuk resource tidak ditemukan."""
    
    def __init__(self, message: str = "Resource not found", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=404, details=details)


class ConflictError(SecureAuthException):
    """Exception untuk konflik data (misal: duplicate entry)."""
    
    def __init__(self, message: str = "Resource conflict", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=409, details=details)


class RateLimitError(SecureAuthException):
    """Exception untuk rate limit exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=429, details=details)


class TokenError(SecureAuthException):
    """Exception untuk error terkait token."""
    
    def __init__(self, message: str = "Invalid token", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=401, details=details)


class AccountLockedException(AuthenticationError):
    """Exception untuk akun yang terkunci."""
    
    def __init__(self, message: str = "Account is locked", locked_until: Optional[str] = None):
        details = {"locked_until": locked_until} if locked_until else None
        super().__init__(message, details=details)


class EmailNotVerifiedException(AuthenticationError):
    """Exception untuk email yang belum diverifikasi."""
    
    def __init__(self, message: str = "Email not verified"):
        super().__init__(message, details={"email_verified": False})


class TwoFactorRequiredException(AuthenticationError):
    """Exception untuk meminta 2FA."""
    
    def __init__(self, message: str = "Two-factor authentication required", session_id: Optional[str] = None):
        details = {"requires_2fa": True}
        if session_id:
            details["session_id"] = session_id
        super().__init__(message, details=details)


class InvalidCredentialsException(AuthenticationError):
    """Exception untuk kredensial yang tidak valid."""
    
    def __init__(self, message: str = "Invalid email or password"):
        super().__init__(message)


class ExpiredTokenException(TokenError):
    """Exception untuk token yang sudah expired."""
    
    def __init__(self, message: str = "Token has expired"):
        super().__init__(message, details={"expired": True})


class InvalidTokenException(TokenError):
    """Exception untuk token yang tidak valid."""
    
    def __init__(self, message: str = "Invalid token"):
        super().__init__(message)


class WeakPasswordException(ValidationError):
    """Exception untuk password yang lemah."""
    
    def __init__(self, message: str = "Password does not meet requirements", errors: Optional[list] = None):
        details = {"password_errors": errors} if errors else None
        super().__init__(message, details=details)


class PasswordReuseException(ValidationError):
    """Exception untuk password yang sudah pernah digunakan."""
    
    def __init__(self, message: str = "Password has been used before"):
        super().__init__(message, details={"password_reuse": True})


class DeviceLimitExceededException(ConflictError):
    """Exception untuk limit device terlampaui."""
    
    def __init__(self, message: str = "Device limit exceeded", max_devices: Optional[int] = None):
        details = {"max_devices": max_devices} if max_devices else None
        super().__init__(message, details=details)


class ServiceUnavailableException(SecureAuthException):
    """Exception untuk service yang tidak tersedia."""
    
    def __init__(self, message: str = "Service temporarily unavailable", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=503, details=details)