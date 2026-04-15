CREATE TABLE IF NOT EXISTS email_verifications
(
    id              UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash        TEXT        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,
    used_at          TIMESTAMPTZ,
    attempts         INT         NOT NULL DEFAULT 0,
    last_attempt_at  TIMESTAMPTZ,
    ip               INET,
    user_agent       TEXT
);

CREATE INDEX IF NOT EXISTS email_verifications_active_idx
    ON email_verifications (user_id, expires_at)
    WHERE used_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS email_verifications_one_active_per_user
    ON email_verifications (user_id)
    WHERE used_at IS NULL;

CREATE INDEX IF NOT EXISTS email_verifications_cleanup_idx
    ON email_verifications (expires_at)
    WHERE used_at IS NULL;
