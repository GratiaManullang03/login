"""
Utils module untuk SecureAuth API.
Berisi utilitas helper seperti validators dan sanitizers.
"""

from app.utils.validators import (
    is_valid_email,
    is_valid_username,
    is_valid_phone_number,
    is_valid_url,
    is_valid_ip_address,
    is_valid_uuid,
    is_strong_password,
    validate_file_extension,
    validate_file_size,
    validate_image_file,
    validate_datetime_string,
    validate_date_string,
    normalize_email,
    normalize_phone_number
)

from app.utils.sanitizers import (
    sanitize_html,
    sanitize_filename,
    sanitize_user_input,
    sanitize_json_data,
    escape_special_chars,
    remove_null_bytes,
    normalize_whitespace,
    truncate_string,
    clean_dict,
    mask_sensitive_data
)

__all__ = [
    # Validators
    "is_valid_email",
    "is_valid_username",
    "is_valid_phone_number",
    "is_valid_url",
    "is_valid_ip_address",
    "is_valid_uuid",
    "is_strong_password",
    "validate_file_extension",
    "validate_file_size",
    "validate_image_file",
    "validate_datetime_string",
    "validate_date_string",
    "normalize_email",
    "normalize_phone_number",
    
    # Sanitizers
    "sanitize_html",
    "sanitize_filename",
    "sanitize_user_input",
    "sanitize_json_data",
    "escape_special_chars",
    "remove_null_bytes",
    "normalize_whitespace",
    "truncate_string",
    "clean_dict",
    "mask_sensitive_data"
]