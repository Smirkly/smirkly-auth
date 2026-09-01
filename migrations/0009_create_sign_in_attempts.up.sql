CREATE TABLE IF NOT EXISTS sign_in_attempts
(
    id               UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    login_identifier TEXT        NOT NULL,
    user_id          UUID REFERENCES users (id) ON DELETE CASCADE,
    ip               INET,
    user_agent       TEXT,
    attempted_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sign_in_attempts_identifier_idx
    ON sign_in_attempts (lower(login_identifier), attempted_at);

CREATE INDEX IF NOT EXISTS sign_in_attempts_user_idx
    ON sign_in_attempts (user_id, attempted_at)
    WHERE user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS sign_in_attempts_ip_idx
    ON sign_in_attempts (ip, attempted_at)
    WHERE ip IS NOT NULL;
