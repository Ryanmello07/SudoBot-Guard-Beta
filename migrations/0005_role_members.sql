CREATE TABLE role_members (
    guild_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    PRIMARY KEY (guild_id, role_id, user_id)
);
