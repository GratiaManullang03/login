-- Init script for PostgreSQL
-- This file will be executed when the container is first created

-- Create extensions if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant all privileges
GRANT ALL PRIVILEGES ON DATABASE secureauth_db TO secureauth;

-- Tabel: users
CREATE TABLE IF NOT EXISTS users (
    u_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    u_email VARCHAR(255) UNIQUE NOT NULL,
    u_username VARCHAR(100) UNIQUE NOT NULL,
    u_password_hash VARCHAR(255) NOT NULL,
    u_is_active BOOLEAN DEFAULT true,
    u_is_verified BOOLEAN DEFAULT false,
    u_is_locked BOOLEAN DEFAULT false,
    u_email_verified_at TIMESTAMPTZ,
    u_created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    u_updated_at TIMESTAMPTZ,
    u_last_login_at TIMESTAMPTZ,
    u_failed_login_attempts INT DEFAULT 0,
    u_locked_until TIMESTAMPTZ,
    u_metadata JSONB,
    u_ip_address VARCHAR(45),
    u_user_agent TEXT
);

-- Tabel: user_sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    us_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    us_user_id UUID NOT NULL REFERENCES users(u_id) ON DELETE CASCADE,
    us_refresh_token_hash VARCHAR(255) UNIQUE NOT NULL,
    us_expires_at TIMESTAMPTZ NOT NULL,
    us_ip_address VARCHAR(45),
    us_user_agent TEXT,
    us_device_info JSONB,
    us_is_active BOOLEAN DEFAULT true,
    us_created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    us_last_activity TIMESTAMPTZ,
    us_logout_reason VARCHAR(255)
);

-- Tabel: password_history
CREATE TABLE IF NOT EXISTS password_history (
    ph_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ph_user_id UUID NOT NULL REFERENCES users(u_id) ON DELETE CASCADE,
    ph_password_hash VARCHAR(255) NOT NULL,
    ph_created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Tabel: login_attempts
CREATE TABLE IF NOT EXISTS login_attempts (
    la_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    la_user_id UUID REFERENCES users(u_id) ON DELETE CASCADE,
    la_email VARCHAR(255) NOT NULL,
    la_ip_address VARCHAR(45),
    la_user_agent TEXT,
    la_success BOOLEAN NOT NULL,
    la_failure_reason VARCHAR(255),
    la_metadata JSONB,
    la_attempted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Tabel: user_tokens
CREATE TABLE IF NOT EXISTS user_tokens (
    ut_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ut_user_id UUID NOT NULL REFERENCES users(u_id) ON DELETE CASCADE,
    ut_token_hash VARCHAR(255) UNIQUE NOT NULL,
    ut_token_type VARCHAR(50) NOT NULL,
    ut_expires_at TIMESTAMPTZ NOT NULL,
    ut_is_used BOOLEAN DEFAULT false,
    ut_used_at TIMESTAMPTZ,
    ut_metadata JSONB,
    ut_created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Tabel: audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
    al_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    al_user_id UUID REFERENCES users(u_id) ON DELETE SET NULL,
    al_action VARCHAR(100) NOT NULL,
    al_entity_type VARCHAR(100),
    al_entity_id UUID,
    al_old_values JSONB,
    al_new_values JSONB,
    al_ip_address VARCHAR(45),
    al_user_agent TEXT,
    al_created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Tabel: user_devices
CREATE TABLE IF NOT EXISTS user_devices (
    ud_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ud_user_id UUID NOT NULL REFERENCES users(u_id) ON DELETE CASCADE,
    ud_device_id VARCHAR(255) NOT NULL,
    ud_device_name VARCHAR(255),
    ud_device_type VARCHAR(100),
    ud_platform VARCHAR(100),
    ud_browser VARCHAR(100),
    ud_is_trusted BOOLEAN DEFAULT false,
    ud_last_used_at TIMESTAMPTZ,
    ud_created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    ud_is_active BOOLEAN DEFAULT true
);

-- Tabel: two_factor_auth
CREATE TABLE IF NOT EXISTS two_factor_auth (
    tfa_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tfa_user_id UUID NOT NULL REFERENCES users(u_id) ON DELETE CASCADE,
    tfa_secret_key TEXT,
    tfa_backup_codes TEXT,
    tfa_is_enabled BOOLEAN DEFAULT false,
    tfa_method VARCHAR(50) NOT NULL,
    tfa_enabled_at TIMESTAMPTZ,
    tfa_last_used_at TIMESTAMPTZ,
    tfa_failed_attempts INT DEFAULT 0
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(us_user_id);
CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(ph_user_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_id ON login_attempts(la_user_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(la_email);
CREATE INDEX IF NOT EXISTS idx_user_tokens_user_id ON user_tokens(ut_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(al_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(al_entity_type, al_entity_id);
CREATE INDEX IF NOT EXISTS idx_user_devices_user_id ON user_devices(ud_user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_two_factor_auth_user_id ON two_factor_auth(tfa_user_id);