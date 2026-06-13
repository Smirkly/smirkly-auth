CREATE TABLE IF NOT EXISTS email_verification_attempts
(
    id           UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    email        TEXT        NOT NULL,
    user_id      UUID REFERENCES users (id) ON DELETE CASCADE,
    ip           INET,
    user_agent   TEXT,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS email_verification_attempts_email_idx
    ON email_verification_attempts (lower(email), attempted_at);

CREATE INDEX IF NOT EXISTS email_verification_attempts_user_idx
    ON email_verification_attempts (user_id, attempted_at)
    WHERE user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS email_verification_attempts_ip_idx
    ON email_verification_attempts (ip, attempted_at)
    WHERE ip IS NOT NULL;
