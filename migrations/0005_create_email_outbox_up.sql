CREATE TABLE email_outbox
(
    id              UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    to_email        TEXT        NOT NULL,
    template        TEXT        NOT NULL,
    payload         JSONB       NOT NULL,
    correlation_id  TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending',
    attempts        INT         NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until    TIMESTAMPTZ,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX email_outbox_ready_idx
    ON email_outbox (status, next_attempt_at)
    WHERE status IN ('pending', 'processing');