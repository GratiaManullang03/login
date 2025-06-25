"""
Script untuk generate security keys yang aman untuk SecureAuth API.
"""

import secrets
import string
import base64
from pathlib import Path


def generate_secret_key(length: int = 64) -> str:
    """Generate random secret key."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_encryption_key() -> str:
    """Generate Fernet-compatible encryption key."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def generate_all_keys() -> dict:
    """Generate all required security keys."""
    return {
        "SECRET_KEY": generate_secret_key(64),
        "ENCRYPTION_KEY": generate_encryption_key(),
        "CSRF_SECRET": generate_secret_key(32),
        "JWT_SECRET_KEY": generate_secret_key(32),
        "DATABASE_ENCRYPTION_KEY": generate_secret_key(32),
        "SESSION_SECRET": generate_secret_key(32),
        "API_KEY_SALT": generate_secret_key(32),
        "PASSWORD_PEPPER": generate_secret_key(32),
    }


def update_env_file(env_path: Path = Path(".env")):
    """Update existing .env file with new keys."""
    if not env_path.exists():
        print(f"❌ .env file not found at {env_path}")
        return
    
    # Read existing content
    with open(env_path, 'r') as f:
        lines = f.readlines()
    
    # Generate new keys
    keys = generate_all_keys()
    
    # Update lines
    updated_lines = []
    for line in lines:
        updated = False
        for key_name, key_value in keys.items():
            if line.startswith(f"{key_name}="):
                # Check if it's a placeholder or needs updating
                if "your-" in line or "Add this" in line or line.strip().endswith('=""'):
                    updated_lines.append(f'{key_name}="{key_value}"\n')
                    print(f"✅ Updated {key_name}")
                    updated = True
                    break
                else:
                    # Key already has a value, keep it
                    updated_lines.append(line)
                    updated = True
                    break
        
        if not updated:
            updated_lines.append(line)
    
    # Write back
    with open(env_path, 'w') as f:
        f.writelines(updated_lines)
    
    print(f"\n✅ Updated .env file: {env_path}")
    print("\n⚠️  IMPORTANT: Keep these keys secret and secure!")


def main():
    """Main function."""
    print("🔐 SecureAuth API Key Generator")
    print("=" * 50)
    
    # Check if .env exists
    env_path = Path(".env")
    
    if env_path.exists():
        response = input("\n.env file exists. Update missing/placeholder keys? (y/n): ")
        if response.lower() == 'y':
            update_env_file(env_path)
        else:
            print("\nGenerating keys for manual update:")
            keys = generate_all_keys()
            print("\n" + "=" * 50)
            for key_name, key_value in keys.items():
                print(f'{key_name}="{key_value}"')
            print("=" * 50)
    else:
        print("\n❌ .env file not found. Creating from .env.example...")
        # You can add logic here to create from template if needed
        
        print("\nGenerated keys:")
        keys = generate_all_keys()
        print("\n" + "=" * 50)
        for key_name, key_value in keys.items():
            print(f'{key_name}="{key_value}"')
        print("=" * 50)


if __name__ == "__main__":
    main()