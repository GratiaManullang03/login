"""
Tests for security functionality.
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.core.security import security, pwd_context
from app.core.exceptions import TokenError


@pytest.mark.unit
@pytest.mark.security
class TestPasswordHashing:
    """Test password hashing functionality."""
    
    def test_hash_password(self):
        """Test password hashing."""
        password = "TestPassword123!"
        hashed = security.hash_password(password)
        
        assert hashed != password
        assert hashed.startswith("$argon2")  # Argon2 hash prefix
        assert len(hashed) > 50
    
    def test_verify_password_correct(self):
        """Test verifying correct password."""
        password = "TestPassword123!"
        hashed = security.hash_password(password)
        
        assert security.verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Test verifying incorrect password."""
        password = "TestPassword123!"
        hashed = security.hash_password(password)
        
        assert security.verify_password("WrongPassword", hashed) is False
    
    def test_password_strength_validation(self):
        """Test password strength validation."""
        # Strong password
        is_valid, errors = security.validate_password_strength("StrongP@ssw0rd!")
        assert is_valid is True
        assert len(errors) == 0
        
        # Weak password - too short
        is_valid, errors = security.validate_password_strength("Weak1!")
        assert is_valid is False
        assert any("at least" in error for error in errors)
        
        # Missing uppercase
        is_valid, errors = security.validate_password_strength("weakpassword123!")
        assert is_valid is False
        assert any("uppercase" in error for error in errors)
        
        # Missing special character
        is_valid, errors = security.validate_password_strength("WeakPassword123")
        assert is_valid is False
        assert any("special" in error for error in errors)
        
        # Common password
        is_valid, errors = security.validate_password_strength("Password123!")
        assert is_valid is False
        assert any("common" in error for error in errors)


@pytest.mark.unit
@pytest.mark.security
class TestJWTTokens:
    """Test JWT token functionality."""
    
    def test_create_access_token(self):
        """Test creating access token."""
        user_id = "test-user-id"
        token = security.create_access_token(
            subject=user_id,
            additional_claims={"email": "test@example.com"}
        )
        
        assert isinstance(token, str)
        assert len(token) > 50
        
        # Decode and verify
        payload = security.decode_token(token)
        assert payload["sub"] == user_id
        assert payload["email"] == "test@example.com"
        assert payload["type"] == "access"
    
    def test_create_refresh_token(self):
        """Test creating refresh token."""
        user_id = "test-user-id"
        token = security.create_refresh_token(subject=user_id)
        
        assert isinstance(token, str)
        assert len(token) > 50
        
        # Decode and verify
        payload = security.decode_token(token, expected_type="refresh")
        assert payload["sub"] == user_id
        assert payload["type"] == "refresh"
        assert "jti" in payload  # JWT ID for tracking
    
    def test_decode_expired_token(self):
        """Test decoding expired token."""
        # Create token with negative expiration
        token = security.create_access_token(
            subject="test",
            expires_delta=timedelta(seconds=-1)
        )
        
        with pytest.raises(TokenError) as exc_info:
            security.decode_token(token)
        
        assert "expired" in str(exc_info.value).lower()
    
    def test_decode_invalid_token(self):
        """Test decoding invalid token."""
        with pytest.raises(TokenError):
            security.decode_token("invalid-token")
    
    def test_decode_wrong_token_type(self):
        """Test decoding token with wrong type."""
        access_token = security.create_access_token(subject="test")
        
        with pytest.raises(TokenError) as exc_info:
            security.decode_token(access_token, expected_type="refresh")
        
        assert "Invalid token type" in str(exc_info.value)


@pytest.mark.unit
@pytest.mark.security
class TestTokenGeneration:
    """Test secure token generation."""
    
    def test_generate_secure_token(self):
        """Test generating secure random token."""
        token1 = security.generate_secure_token()
        token2 = security.generate_secure_token()
        
        assert isinstance(token1, str)
        assert len(token1) >= 32
        assert token1 != token2  # Should be unique
    
    def test_generate_numeric_token(self):
        """Test generating numeric token."""
        token = security.generate_numeric_token(6)
        
        assert isinstance(token, str)
        assert len(token) == 6
        assert token.isdigit()
    
    def test_generate_backup_codes(self):
        """Test generating backup codes."""
        codes = security.generate_backup_codes(count=5)
        
        assert len(codes) == 5
        assert all("-" in code for code in codes)  # Should be formatted
        assert len(set(codes)) == 5  # All unique
    
    def test_hash_token(self):
        """Test token hashing for storage."""
        token = "test-token"
        hashed = security.hash_token(token)
        
        assert hashed != token
        assert isinstance(hashed, str)
        assert len(hashed) == 64  # SHA256 hex length


@pytest.mark.unit
@pytest.mark.security
class TestEncryption:
    """Test encryption functionality."""
    
    def test_encrypt_decrypt(self):
        """Test encrypting and decrypting data."""
        data = "sensitive data"
        
        encrypted = security.encrypt(data)
        assert encrypted != data
        assert isinstance(encrypted, str)
        
        decrypted = security.decrypt(encrypted)
        assert decrypted == data
    
    def test_encrypt_different_outputs(self):
        """Test that encryption produces different outputs."""
        data = "test data"
        
        encrypted1 = security.encrypt(data)
        encrypted2 = security.encrypt(data)
        
        # Different ciphertexts due to different IVs
        assert encrypted1 != encrypted2
        
        # But both decrypt to same value
        assert security.decrypt(encrypted1) == data
        assert security.decrypt(encrypted2) == data
    
    def test_decrypt_invalid_data(self):
        """Test decrypting invalid data."""
        from app.core.exceptions import ValidationError
        
        with pytest.raises(ValidationError) as exc_info:
            security.decrypt("invalid-encrypted-data")
        
        assert "Failed to decrypt" in str(exc_info.value)


@pytest.mark.unit
@pytest.mark.security
class TestSecurityHelpers:
    """Test security helper functions."""
    
    def test_password_history_check(self):
        """Test password history checking."""
        from app.models.password_history import PasswordHistory
        
        # Create mock password history
        password1 = "OldPassword1!"
        password2 = "OldPassword2!"
        current_password = "CurrentPassword3!"
        
        # Mock history entries
        history = [
            type('MockHistory', (), {
                'ph_user_id': 'test-user',
                'check_password': lambda p: security.verify_password(p, security.hash_password(password1))
            })(),
            type('MockHistory', (), {
                'ph_user_id': 'test-user',
                'check_password': lambda p: security.verify_password(p, security.hash_password(password2))
            })()
        ]
        
        # Check reuse of old password
        assert PasswordHistory.check_password_reuse(
            'test-user', password1, history
        ) is True
        
        # Check new password
        assert PasswordHistory.check_password_reuse(
            'test-user', "NewPassword4!", history
        ) is False