CREATE TABLE IF NOT EXISTS password_resets
(
    id              UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash       TEXT        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,
    used_at          TIMESTAMPTZ,
    attempts         INT         NOT NULL DEFAULT 0,
    last_attempt_at  TIMESTAMPTZ,
    ip               INET,
    user_agent       TEXT
);

CREATE INDEX IF NOT EXISTS password_resets_active_idx
    ON password_resets (user_id, expires_at)
    WHERE used_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS password_resets_one_active_per_user
    ON password_resets (user_id)
    WHERE used_at IS NULL;

CREATE INDEX IF NOT EXISTS password_resets_cleanup_idx
    ON password_resets (expires_at)
    WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS password_reset_attempts
(
    id           UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    email        TEXT        NOT NULL,
    user_id      UUID REFERENCES users (id) ON DELETE CASCADE,
    ip           INET,
    user_agent   TEXT,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS password_reset_attempts_email_idx
    ON password_reset_attempts (lower(email), attempted_at);

CREATE INDEX IF NOT EXISTS password_reset_attempts_user_idx
    ON password_reset_attempts (user_id, attempted_at)
    WHERE user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS password_reset_attempts_ip_idx
    ON password_reset_attempts (ip, attempted_at)
    WHERE ip IS NOT NULL;
