CREATE TABLE role_baselines (
    guild_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    permissions BIGINT NOT NULL,
    name TEXT,
    position INT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by BIGINT,
    PRIMARY KEY (guild_id, role_id)
);
