"""
Validator utilities untuk SecureAuth API.
Menyediakan fungsi-fungsi validasi untuk berbagai jenis input.
"""

import re
import ipaddress
from typing import Optional, List, Tuple, Union
from datetime import datetime
from urllib.parse import urlparse
from uuid import UUID
from pathlib import Path
import phonenumbers
from email_validator import validate_email as validate_email_lib, EmailNotValidError


# Regex patterns
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,50}$')
STRONG_PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
)
URL_PATTERN = re.compile(
    r'^https?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE
)

# File validation constants
ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'}
ALLOWED_DOCUMENT_EXTENSIONS = {'.pdf', '.doc', '.docx', '.txt', '.odt', '.rtf'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB default
MAX_IMAGE_SIZE = 5 * 1024 * 1024   # 5MB for images


def is_valid_email(email: str) -> bool:
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if email is valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
    
    try:
        # Use email-validator library for comprehensive validation
        validate_email_lib(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


def is_valid_username(username: str) -> bool:
    """
    Validate username format.
    
    Rules:
    - 3-50 characters
    - Only alphanumeric, underscore, and hyphen
    - Cannot start or end with special characters
    
    Args:
        username: Username to validate
        
    Returns:
        True if username is valid, False otherwise
    """
    if not username or not isinstance(username, str):
        return False
    
    # Check pattern
    if not USERNAME_PATTERN.match(username):
        return False
    
    # Additional checks
    if username.startswith(('-', '_')) or username.endswith(('-', '_')):
        return False
    
    # Check for consecutive special characters
    if '--' in username or '__' in username:
        return False
    
    # Reserved usernames
    reserved_usernames = {
        'admin', 'root', 'system', 'api', 'auth', 'oauth', 'test',
        'user', 'users', 'profile', 'profiles', 'account', 'accounts',
        'login', 'logout', 'register', 'signup', 'signin', 'signout'
    }
    
    if username.lower() in reserved_usernames:
        return False
    
    return True


def is_valid_phone_number(phone: str, region: str = None) -> bool:
    """
    Validate phone number format.
    
    Args:
        phone: Phone number to validate
        region: ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB')
        
    Returns:
        True if phone number is valid, False otherwise
    """
    if not phone or not isinstance(phone, str):
        return False
    
    try:
        # Parse phone number
        if region:
            parsed = phonenumbers.parse(phone, region)
        else:
            # Try to parse with international format
            parsed = phonenumbers.parse(phone, None)
        
        # Check if valid
        return phonenumbers.is_valid_number(parsed)
    except phonenumbers.NumberParseException:
        return False


def is_valid_url(url: str, require_https: bool = False) -> bool:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        require_https: Whether to require HTTPS protocol
        
    Returns:
        True if URL is valid, False otherwise
    """
    if not url or not isinstance(url, str):
        return False
    
    # Basic regex check
    if not URL_PATTERN.match(url):
        return False
    
    try:
        # Parse URL for additional validation
        parsed = urlparse(url)
        
        # Check scheme
        if require_https and parsed.scheme != 'https':
            return False
        
        if parsed.scheme not in ('http', 'https'):
            return False
        
        # Check netloc (domain)
        if not parsed.netloc:
            return False
        
        # Prevent some common issues
        if '..' in url or '//' in url[8:]:  # Skip protocol //
            return False
        
        return True
    except Exception:
        return False


def is_valid_ip_address(ip: str, version: Optional[int] = None) -> bool:
    """
    Validate IP address format.
    
    Args:
        ip: IP address to validate
        version: IP version (4 or 6), None for both
        
    Returns:
        True if IP address is valid, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        if version is None:
            return True
        elif version == 4:
            return isinstance(ip_obj, ipaddress.IPv4Address)
        elif version == 6:
            return isinstance(ip_obj, ipaddress.IPv6Address)
        else:
            return False
    except ValueError:
        return False


def is_valid_uuid(uuid_string: str, version: Optional[int] = None) -> bool:
    """
    Validate UUID format.
    
    Args:
        uuid_string: UUID string to validate
        version: UUID version (1-5), None for any version
        
    Returns:
        True if UUID is valid, False otherwise
    """
    if not uuid_string or not isinstance(uuid_string, str):
        return False
    
    try:
        uuid_obj = UUID(uuid_string)
        
        if version is None:
            return True
        else:
            return uuid_obj.version == version
    except (ValueError, AttributeError):
        return False


def is_strong_password(
    password: str,
    min_length: int = 8,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_numbers: bool = True,
    require_special: bool = True,
    check_common: bool = True
) -> Tuple[bool, List[str]]:
    """
    Validate password strength with detailed requirements.
    
    Args:
        password: Password to validate
        min_length: Minimum password length
        require_uppercase: Require uppercase letters
        require_lowercase: Require lowercase letters
        require_numbers: Require numbers
        require_special: Require special characters
        check_common: Check against common passwords
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    if not password or not isinstance(password, str):
        return False, ["Password is required"]
    
    errors = []
    
    # Length check
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters long")
    
    # Character requirements
    if require_uppercase and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if require_lowercase and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if require_numbers and not re.search(r'\d', password):
        errors.append("Password must contain at least one number")
    
    if require_special and not re.search(r'[@$!%*?&]', password):
        errors.append("Password must contain at least one special character (@$!%*?&)")
    
    # Common password check
    if check_common:
        common_passwords = {
            'password', '12345678', 'qwerty', '123456789', 'password123',
            'admin', 'letmein', 'welcome', 'monkey', '1234567890',
            'password1', 'qwerty123', 'abc123', 'Password1', 'password123'
        }
        
        if password.lower() in common_passwords:
            errors.append("Password is too common")
    
    # Sequential characters check
    if any(password[i:i+3].lower() in 'abcdefghijklmnopqrstuvwxyz' for i in range(len(password)-2)):
        errors.append("Password contains sequential letters")
    
    if any(password[i:i+3] in '0123456789' for i in range(len(password)-2)):
        errors.append("Password contains sequential numbers")
    
    return len(errors) == 0, errors


def validate_file_extension(
    filename: str,
    allowed_extensions: Optional[set] = None,
    case_sensitive: bool = False
) -> bool:
    """
    Validate file extension.
    
    Args:
        filename: Filename to validate
        allowed_extensions: Set of allowed extensions (with dots)
        case_sensitive: Whether extension check is case sensitive
        
    Returns:
        True if extension is valid, False otherwise
    """
    if not filename or not isinstance(filename, str):
        return False
    
    # Get extension
    path = Path(filename)
    extension = path.suffix
    
    if not extension:
        return False
    
    if allowed_extensions is None:
        # Allow common safe extensions
        allowed_extensions = ALLOWED_IMAGE_EXTENSIONS | ALLOWED_DOCUMENT_EXTENSIONS
    
    if not case_sensitive:
        extension = extension.lower()
        allowed_extensions = {ext.lower() for ext in allowed_extensions}
    
    return extension in allowed_extensions


def validate_file_size(
    file_size: int,
    max_size: Optional[int] = None,
    min_size: int = 0
) -> Tuple[bool, Optional[str]]:
    """
    Validate file size.
    
    Args:
        file_size: File size in bytes
        max_size: Maximum allowed size in bytes
        min_size: Minimum allowed size in bytes
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(file_size, int) or file_size < 0:
        return False, "Invalid file size"
    
    if file_size < min_size:
        return False, f"File size must be at least {min_size} bytes"
    
    if max_size is None:
        max_size = MAX_FILE_SIZE
    
    if file_size > max_size:
        # Convert to human readable
        max_mb = max_size / (1024 * 1024)
        return False, f"File size must not exceed {max_mb:.1f} MB"
    
    return True, None


def validate_image_file(
    filename: str,
    file_size: Optional[int] = None
) -> Tuple[bool, Optional[str]]:
    """
    Validate image file.
    
    Args:
        filename: Image filename
        file_size: File size in bytes (optional)
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check extension
    if not validate_file_extension(filename, ALLOWED_IMAGE_EXTENSIONS):
        return False, "Invalid image file extension"
    
    # Check size if provided
    if file_size is not None:
        is_valid, error = validate_file_size(file_size, MAX_IMAGE_SIZE)
        if not is_valid:
            return False, error
    
    return True, None


def validate_datetime_string(
    datetime_str: str,
    format: str = "%Y-%m-%dT%H:%M:%S"
) -> bool:
    """
    Validate datetime string format.
    
    Args:
        datetime_str: Datetime string to validate
        format: Expected datetime format
        
    Returns:
        True if datetime string is valid, False otherwise
    """
    if not datetime_str or not isinstance(datetime_str, str):
        return False
    
    try:
        datetime.strptime(datetime_str, format)
        return True
    except ValueError:
        return False


def validate_date_string(
    date_str: str,
    format: str = "%Y-%m-%d"
) -> bool:
    """
    Validate date string format.
    
    Args:
        date_str: Date string to validate
        format: Expected date format
        
    Returns:
        True if date string is valid, False otherwise
    """
    return validate_datetime_string(date_str, format)


def normalize_email(email: str) -> str:
    """
    Normalize email address.
    
    Args:
        email: Email address to normalize
        
    Returns:
        Normalized email address
    """
    if not email:
        return email
    
    # Convert to lowercase and strip whitespace
    email = email.lower().strip()
    
    # Handle Gmail aliases (remove dots and everything after +)
    if '@gmail.com' in email:
        local, domain = email.split('@')
        # Remove dots
        local = local.replace('.', '')
        # Remove everything after +
        if '+' in local:
            local = local.split('+')[0]
        email = f"{local}@{domain}"
    
    return email


def normalize_phone_number(
    phone: str,
    region: str = 'US',
    format: phonenumbers.PhoneNumberFormat = phonenumbers.PhoneNumberFormat.E164
) -> Optional[str]:
    """
    Normalize phone number to standard format.
    
    Args:
        phone: Phone number to normalize
        region: Default region code
        format: Output format (E164, INTERNATIONAL, NATIONAL)
        
    Returns:
        Normalized phone number or None if invalid
    """
    if not phone:
        return None
    
    try:
        # Parse phone number
        parsed = phonenumbers.parse(phone, region)
        
        # Check if valid
        if not phonenumbers.is_valid_number(parsed):
            return None
        
        # Format phone number
        return phonenumbers.format_number(parsed, format)
    except phonenumbers.NumberParseException:
        return None