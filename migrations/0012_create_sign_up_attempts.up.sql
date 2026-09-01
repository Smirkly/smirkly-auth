CREATE TABLE IF NOT EXISTS sign_up_attempts
(
    id           UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    ip           INET        NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sign_up_attempts_ip_idx
    ON sign_up_attempts (ip, attempted_at);
