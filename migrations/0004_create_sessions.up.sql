CREATE TABLE sessions
(
    id                     UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    user_id                UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id              UUID        REFERENCES devices (id) ON DELETE SET NULL,
    refresh_token_hash     TEXT        NOT NULL,
    ip                     INET,
    user_agent             TEXT,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at           TIMESTAMPTZ,
    expires_at             TIMESTAMPTZ NOT NULL,
    revoked_at             TIMESTAMPTZ,
    token_family_id        UUID        NOT NULL,
    replaced_by_session_id UUID        REFERENCES sessions (id) ON DELETE SET NULL
);
