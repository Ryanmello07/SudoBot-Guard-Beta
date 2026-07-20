CREATE TABLE bot_admins (
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE role_pairs (
    id BIGSERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    standard_role_id BIGINT NOT NULL,
    permission_role_id BIGINT NOT NULL,
    session_minutes INTEGER NOT NULL,
    alert_tier TEXT NOT NULL DEFAULT 'info',
    created_by BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (guild_id, standard_role_id),
    UNIQUE (guild_id, permission_role_id)
);

CREATE TABLE totp_enrollments (
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    totp_secret_encrypted BYTEA NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT false,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE yubikey_enrollments (
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    yubikey_public_id TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT true,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE enrollment_requests (
    id BIGSERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    factor_type TEXT NOT NULL CHECK (factor_type IN ('totp', 'yubikey')),
    action TEXT NOT NULL CHECK (action IN ('add', 'regenerate')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'expired', 'fulfilled')),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by BIGINT,
    approved_at TIMESTAMPTZ,
    window_minutes INTEGER,
    window_expires_at TIMESTAMPTZ
);

CREATE TABLE backup_codes (
    id BIGSERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE totp_replay_ledger (
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    time_step BIGINT NOT NULL,
    used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, user_id, time_step)
);

CREATE TABLE auth_attempts (
    id BIGSERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    success BOOLEAN NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id BIGSERIAL PRIMARY KEY,
    guild_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    role_pair_id BIGINT NOT NULL REFERENCES role_pairs(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoke_reason TEXT
);

CREATE TABLE log_channels (
    guild_id BIGINT PRIMARY KEY,
    channel_id BIGINT NOT NULL
);

CREATE TABLE log_sequence (
    guild_id BIGINT PRIMARY KEY,
    next_seq BIGINT NOT NULL DEFAULT 1
);

CREATE INDEX idx_auth_attempts_guild_user_time ON auth_attempts (guild_id, user_id, attempted_at);
CREATE INDEX idx_sessions_expiry ON sessions (expires_at) WHERE revoked_at IS NULL;
