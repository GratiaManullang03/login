"""
Modul keamanan terpusat untuk SecureAuth API.
Menangani password hashing, JWT generation/validation, enkripsi, dan utilitas keamanan lainnya.
"""

import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple, List
import re

from passlib.context import CryptContext
from jose import jwt, JWTError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from app.core.config import settings
from app.core.exceptions import TokenError, ValidationError


# Password hashing context dengan Argon2
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__rounds=4,
    argon2__memory_cost=65536,
    argon2__parallelism=2,
    argon2__hash_len=32,
    argon2__salt_len=16
)


class Security:
    """Kelas untuk operasi keamanan."""
    
    def __init__(self):
        """Inisialisasi security dengan encryption key."""
        self._fernet = self._create_fernet()
    
    def _create_fernet(self) -> Fernet:
        """
        Membuat Fernet instance untuk enkripsi.
        Menggunakan PBKDF2 untuk derive key dari ENCRYPTION_KEY.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=settings.SECRET_KEY.encode()[:16],
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(
            kdf.derive(settings.ENCRYPTION_KEY.encode())
        )
        return Fernet(key)
    
    # Password Operations
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash password menggunakan Argon2.
        
        Args:
            password: Plain text password
            
        Returns:
            Hashed password
        """
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verifikasi password terhadap hash.
        
        Args:
            plain_password: Plain text password
            hashed_password: Hashed password
            
        Returns:
            True jika password cocok, False jika tidak
        """
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, List[str]]:
        """
        Validasi kekuatan password berdasarkan policy.
        
        Args:
            password: Password yang akan divalidasi
            
        Returns:
            Tuple (is_valid, list_of_errors)
        """
        errors = []
        
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            errors.append(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
        
        if settings.PASSWORD_REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")
        
        if settings.PASSWORD_REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")
        
        if settings.PASSWORD_REQUIRE_NUMBERS and not re.search(r"\d", password):
            errors.append("Password must contain at least one number")
        
        if settings.PASSWORD_REQUIRE_SPECIAL and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("Password must contain at least one special character")
        
        # Check for common patterns
        if password.lower() in ["password", "12345678", "qwerty", "admin"]:
            errors.append("Password is too common")
        
        return (len(errors) == 0, errors)
    
    # JWT Operations
    @staticmethod
    def create_access_token(
        subject: str,
        expires_delta: Optional[timedelta] = None,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Membuat JWT access token.
        
        Args:
            subject: Subject JWT (biasanya user_id)
            expires_delta: Custom expiration time
            additional_claims: Claims tambahan untuk ditambahkan ke token
            
        Returns:
            Encoded JWT token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + settings.access_token_expire_timedelta
        
        to_encode = {
            "sub": subject,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "access"
        }
        
        if additional_claims:
            to_encode.update(additional_claims)
        
        encoded_jwt = jwt.encode(
            to_encode,
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )
        return encoded_jwt
    
    @staticmethod
    def create_refresh_token(
        subject: str,
        expires_delta: Optional[timedelta] = None,
        additional_claims: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Membuat JWT refresh token.
        
        Args:
            subject: Subject JWT (biasanya user_id)
            expires_delta: Custom expiration time
            additional_claims: Claims tambahan
            
        Returns:
            Encoded JWT refresh token
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + settings.refresh_token_expire_timedelta
        
        to_encode = {
            "sub": subject,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "type": "refresh",
            "jti": secrets.token_urlsafe(32)  # JWT ID untuk tracking
        }
        
        if additional_claims:
            to_encode.update(additional_claims)
        
        encoded_jwt = jwt.encode(
            to_encode,
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )
        return encoded_jwt
    
    @staticmethod
    def decode_token(token: str, expected_type: str = "access") -> Dict[str, Any]:
        """
        Decode dan validasi JWT token.
        
        Args:
            token: JWT token
            expected_type: Tipe token yang diharapkan ("access" atau "refresh")
            
        Returns:
            Decoded token payload
            
        Raises:
            TokenError: Jika token tidak valid
        """
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )
            
            # Validasi tipe token
            if payload.get("type") != expected_type:
                raise TokenError(f"Invalid token type. Expected {expected_type}")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise TokenError("Token has expired")
        except jwt.JWTClaimsError:
            raise TokenError("Invalid token claims")
        except JWTError:
            raise TokenError("Invalid token")
    
    # Token Generation untuk Non-JWT
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """
        Generate secure random token untuk berbagai keperluan.
        
        Args:
            length: Panjang token
            
        Returns:
            Secure random token
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_numeric_token(length: int = 6) -> str:
        """
        Generate numeric token untuk OTP.
        
        Args:
            length: Panjang token
            
        Returns:
            Numeric token
        """
        return ''.join(secrets.choice(string.digits) for _ in range(length))
    
    @staticmethod
    def generate_backup_codes(count: int = 10, length: int = 8) -> List[str]:
        """
        Generate backup codes untuk 2FA.
        
        Args:
            count: Jumlah backup codes
            length: Panjang setiap code
            
        Returns:
            List of backup codes
        """
        codes = []
        for _ in range(count):
            code = ''.join(
                secrets.choice(string.ascii_uppercase + string.digits) 
                for _ in range(length)
            )
            # Format dengan dash untuk readability
            formatted_code = '-'.join([code[i:i+4] for i in range(0, len(code), 4)])
            codes.append(formatted_code)
        return codes
    
    # Encryption Operations
    def encrypt(self, data: str) -> str:
        """
        Enkripsi data menggunakan Fernet.
        
        Args:
            data: Data yang akan dienkripsi
            
        Returns:
            Encrypted data (base64 encoded)
        """
        return self._fernet.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Dekripsi data menggunakan Fernet.
        
        Args:
            encrypted_data: Data terenkripsi (base64 encoded)
            
        Returns:
            Decrypted data
            
        Raises:
            ValidationError: Jika dekripsi gagal
        """
        try:
            return self._fernet.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            raise ValidationError("Failed to decrypt data")
    
    # Hash Operations untuk Token Storage
    @staticmethod
    def hash_token(token: str) -> str:
        """
        Hash token untuk penyimpanan aman di database.
        Menggunakan SHA256 karena tidak perlu verifikasi seperti password.
        
        Args:
            token: Token yang akan di-hash
            
        Returns:
            Hashed token
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(token.encode())
        return digest.finalize().hex()


# Global security instance
security = Security()