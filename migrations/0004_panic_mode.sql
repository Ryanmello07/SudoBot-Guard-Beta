CREATE TABLE voter_roles (
    guild_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (guild_id, role_id)
);

CREATE TABLE panic_channels (
    guild_id BIGINT PRIMARY KEY,
    channel_id BIGINT NOT NULL
);

CREATE TABLE panic_state (
    guild_id BIGINT PRIMARY KEY,
    active BOOLEAN NOT NULL DEFAULT false,
    triggered_by BIGINT,
    triggered_at TIMESTAMPTZ,
    vote_channel_id BIGINT,
    vote_message_id BIGINT,
    cooldown_until TIMESTAMPTZ
);

CREATE TABLE panic_votes (
    guild_id BIGINT NOT NULL,
    voter_id BIGINT NOT NULL,
    voted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, voter_id)
);
