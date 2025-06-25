"""
Sanitizer utilities untuk SecureAuth API.
Menyediakan fungsi-fungsi untuk membersihkan dan mengamankan input pengguna.
"""

import re
import html
import unicodedata
from typing import Any, Dict, List, Optional, Union
from pathlib import Path
import bleach
from urllib.parse import quote, unquote


# Allowed HTML tags and attributes for sanitization
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u', 'i', 'b', 'code', 'pre', 'blockquote', 'ul', 'ol', 'li']
ALLOWED_ATTRIBUTES = {}

# Regex patterns for sanitization
CONTROL_CHARS_PATTERN = re.compile(r'[\x00-\x1F\x7F-\x9F]')
MULTIPLE_SPACES_PATTERN = re.compile(r'\s+')
FILENAME_INVALID_CHARS_PATTERN = re.compile(r'[<>:"/\\|?*\x00-\x1F]')
SQL_KEYWORDS_PATTERN = re.compile(
    r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|FROM|WHERE)\b',
    re.IGNORECASE
)


def sanitize_html(
    html_content: str,
    allowed_tags: Optional[List[str]] = None,
    allowed_attributes: Optional[Dict[str, List[str]]] = None,
    strip: bool = True
) -> str:
    """
    Sanitize HTML content to prevent XSS attacks.
    
    Args:
        html_content: HTML content to sanitize
        allowed_tags: List of allowed HTML tags
        allowed_attributes: Dict of allowed attributes per tag
        strip: Whether to strip disallowed tags or escape them
        
    Returns:
        Sanitized HTML content
    """
    if not html_content:
        return ""
    
    if not isinstance(html_content, str):
        return ""
    
    # Use default allowed tags if not specified
    if allowed_tags is None:
        allowed_tags = ALLOWED_TAGS
    
    if allowed_attributes is None:
        allowed_attributes = ALLOWED_ATTRIBUTES
    
    # Clean HTML using bleach
    cleaned = bleach.clean(
        html_content,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=strip,
        strip_comments=True
    )
    
    # Additional sanitization
    # Remove any remaining script tags (belt and suspenders)
    cleaned = re.sub(r'<script[^>]*>.*?</script>', '', cleaned, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r'javascript:', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'on\w+\s*=', '', cleaned, flags=re.IGNORECASE)
    
    return cleaned


def sanitize_filename(
    filename: str,
    max_length: int = 255,
    allow_unicode: bool = False,
    replacement_char: str = '_'
) -> str:
    """
    Sanitize filename for safe file system storage.
    
    Args:
        filename: Filename to sanitize
        max_length: Maximum allowed length
        allow_unicode: Whether to allow unicode characters
        replacement_char: Character to replace invalid chars with
        
    Returns:
        Sanitized filename
    """
    if not filename:
        return "unnamed"
    
    # Get base name and extension
    path = Path(filename)
    name = path.stem
    extension = path.suffix
    
    # Remove null bytes
    name = name.replace('\x00', '')
    
    # Normalize unicode if needed
    if not allow_unicode:
        # Convert to ASCII
        name = unicodedata.normalize('NFKD', name)
        name = name.encode('ascii', 'ignore').decode('ascii')
    
    # Replace invalid characters
    name = FILENAME_INVALID_CHARS_PATTERN.sub(replacement_char, name)
    
    # Remove leading/trailing dots and spaces
    name = name.strip('. ')
    
    # Replace multiple underscores with single
    name = re.sub(f'{replacement_char}+', replacement_char, name)
    
    # Ensure filename is not empty
    if not name:
        name = "unnamed"
    
    # Truncate if too long (leaving room for extension)
    max_name_length = max_length - len(extension)
    if len(name) > max_name_length:
        name = name[:max_name_length]
    
    # Prevent reserved filenames on Windows
    reserved_names = {
        'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4',
        'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2',
        'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    }
    
    if name.upper() in reserved_names:
        name = f"{replacement_char}{name}"
    
    # Reconstruct filename
    sanitized = f"{name}{extension}"
    
    return sanitized


def sanitize_user_input(
    input_text: str,
    max_length: Optional[int] = None,
    allow_newlines: bool = False,
    allow_html: bool = False,
    strip_whitespace: bool = True
) -> str:
    """
    General purpose sanitizer for user text input.
    
    Args:
        input_text: Text to sanitize
        max_length: Maximum allowed length
        allow_newlines: Whether to allow newline characters
        allow_html: Whether to allow HTML (will be sanitized)
        strip_whitespace: Whether to strip leading/trailing whitespace
        
    Returns:
        Sanitized text
    """
    if not input_text:
        return ""
    
    if not isinstance(input_text, str):
        input_text = str(input_text)
    
    # Remove null bytes and control characters
    text = remove_null_bytes(input_text)
    text = CONTROL_CHARS_PATTERN.sub('', text)
    
    # Handle newlines
    if not allow_newlines:
        text = text.replace('\n', ' ').replace('\r', ' ')
    
    # Normalize whitespace
    text = normalize_whitespace(text)
    
    # Strip whitespace if requested
    if strip_whitespace:
        text = text.strip()
    
    # Handle HTML
    if not allow_html:
        # Escape HTML entities
        text = html.escape(text)
    else:
        # Sanitize HTML
        text = sanitize_html(text)
    
    # Truncate if needed
    if max_length and len(text) > max_length:
        text = truncate_string(text, max_length)
    
    return text


def sanitize_json_data(
    data: Union[Dict, List, Any],
    max_depth: int = 10,
    max_string_length: Optional[int] = None,
    remove_nulls: bool = False
) -> Union[Dict, List, Any]:
    """
    Recursively sanitize JSON-like data structures.
    
    Args:
        data: Data to sanitize
        max_depth: Maximum nesting depth
        max_string_length: Maximum string length
        remove_nulls: Whether to remove null values
        
    Returns:
        Sanitized data
    """
    def _sanitize(obj: Any, depth: int = 0) -> Any:
        if depth > max_depth:
            return None
        
        if isinstance(obj, dict):
            sanitized = {}
            for key, value in obj.items():
                # Sanitize key
                if not isinstance(key, str):
                    key = str(key)
                key = sanitize_user_input(key, max_length=100)
                
                # Sanitize value
                value = _sanitize(value, depth + 1)
                
                # Skip nulls if requested
                if remove_nulls and value is None:
                    continue
                
                sanitized[key] = value
            return sanitized
        
        elif isinstance(obj, list):
            return [_sanitize(item, depth + 1) for item in obj]
        
        elif isinstance(obj, str):
            sanitized = sanitize_user_input(obj, max_length=max_string_length)
            return sanitized
        
        elif isinstance(obj, (int, float, bool)):
            return obj
        
        elif obj is None:
            return None
        
        else:
            # Convert other types to string and sanitize
            return sanitize_user_input(str(obj), max_length=max_string_length)
    
    return _sanitize(data)


def escape_special_chars(
    text: str,
    chars_to_escape: str = '<>&"\''
) -> str:
    """
    Escape special characters in text.
    
    Args:
        text: Text to escape
        chars_to_escape: Characters to escape
        
    Returns:
        Escaped text
    """
    if not text:
        return ""
    
    escape_map = {
        '<': '&lt;',
        '>': '&gt;',
        '&': '&amp;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;'
    }
    
    for char in chars_to_escape:
        if char in escape_map:
            text = text.replace(char, escape_map[char])
    
    return text


def remove_null_bytes(text: str) -> str:
    """
    Remove null bytes from text.
    
    Args:
        text: Text to clean
        
    Returns:
        Text without null bytes
    """
    if not text:
        return ""
    
    return text.replace('\x00', '').replace('\0', '')


def normalize_whitespace(
    text: str,
    preserve_newlines: bool = True
) -> str:
    """
    Normalize whitespace in text.
    
    Args:
        text: Text to normalize
        preserve_newlines: Whether to preserve newline characters
        
    Returns:
        Text with normalized whitespace
    """
    if not text:
        return ""
    
    if preserve_newlines:
        # Normalize spaces within lines
        lines = text.split('\n')
        normalized_lines = []
        for line in lines:
            # Replace multiple spaces with single space
            line = MULTIPLE_SPACES_PATTERN.sub(' ', line)
            normalized_lines.append(line.strip())
        return '\n'.join(normalized_lines)
    else:
        # Replace all whitespace with single space
        return MULTIPLE_SPACES_PATTERN.sub(' ', text).strip()


def truncate_string(
    text: str,
    max_length: int,
    suffix: str = '...'
) -> str:
    """
    Truncate string to maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncated
        
    Returns:
        Truncated text
    """
    if not text or len(text) <= max_length:
        return text
    
    # Account for suffix length
    truncate_at = max_length - len(suffix)
    if truncate_at <= 0:
        return text[:max_length]
    
    return text[:truncate_at] + suffix


def clean_dict(
    data: Dict[str, Any],
    remove_keys: Optional[List[str]] = None,
    remove_empty: bool = False,
    remove_private: bool = True
) -> Dict[str, Any]:
    """
    Clean dictionary by removing unwanted keys.
    
    Args:
        data: Dictionary to clean
        remove_keys: List of keys to remove
        remove_empty: Whether to remove empty values
        remove_private: Whether to remove keys starting with underscore
        
    Returns:
        Cleaned dictionary
    """
    if not isinstance(data, dict):
        return {}
    
    cleaned = {}
    remove_keys = remove_keys or []
    
    for key, value in data.items():
        # Skip keys to remove
        if key in remove_keys:
            continue
        
        # Skip private keys if requested
        if remove_private and key.startswith('_'):
            continue
        
        # Skip empty values if requested
        if remove_empty:
            if value is None or value == '' or value == [] or value == {}:
                continue
        
        # Recursively clean nested dicts
        if isinstance(value, dict):
            value = clean_dict(value, remove_keys, remove_empty, remove_private)
        
        cleaned[key] = value
    
    return cleaned


def mask_sensitive_data(
    text: str,
    patterns: Optional[Dict[str, str]] = None,
    mask_char: str = '*',
    partial_mask: bool = True
) -> str:
    """
    Mask sensitive data in text (e.g., credit cards, SSN).
    
    Args:
        text: Text containing sensitive data
        patterns: Dict of pattern_name: regex_pattern
        mask_char: Character to use for masking
        partial_mask: Whether to partially mask (show first/last few chars)
        
    Returns:
        Text with masked sensitive data
    """
    if not text:
        return ""
    
    # Default patterns for common sensitive data
    if patterns is None:
        patterns = {
            'credit_card': r'\b(?:\d[ -]*?){13,19}\b',
            'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\+?1?\d{10,15}\b',
            'api_key': r'\b(sk_|pk_|api_)[a-zA-Z0-9]{20,}\b'
        }
    
    masked_text = text
    
    for pattern_name, pattern in patterns.items():
        regex = re.compile(pattern)
        
        def mask_match(match):
            matched_text = match.group(0)
            
            if not partial_mask:
                # Full mask
                return mask_char * len(matched_text)
            
            # Partial mask based on type
            if pattern_name == 'credit_card':
                # Show last 4 digits
                visible_end = 4
                if len(matched_text) > visible_end:
                    masked_part = mask_char * (len(matched_text) - visible_end)
                    return masked_part + matched_text[-visible_end:]
            
            elif pattern_name == 'email':
                # Show first 2 chars and domain
                parts = matched_text.split('@')
                if len(parts) == 2 and len(parts[0]) > 2:
                    username = parts[0][:2] + mask_char * (len(parts[0]) - 2)
                    return f"{username}@{parts[1]}"
            
            elif pattern_name == 'ssn':
                # Show last 4 digits
                digits = re.sub(r'\D', '', matched_text)
                if len(digits) == 9:
                    return f"{mask_char * 3}-{mask_char * 2}-{digits[-4:]}"
            
            # Default partial mask: show first and last 2 chars
            if len(matched_text) > 4:
                visible_start = 2
                visible_end = 2
                masked_middle = mask_char * (len(matched_text) - visible_start - visible_end)
                return matched_text[:visible_start] + masked_middle + matched_text[-visible_end:]
            
            return mask_char * len(matched_text)
        
        masked_text = regex.sub(mask_match, masked_text)
    
    return masked_text