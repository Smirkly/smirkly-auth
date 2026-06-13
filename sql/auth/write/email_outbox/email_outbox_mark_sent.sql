UPDATE email_outbox
SET
    status       = 'sent',
    payload      = '{}'::jsonb,
    locked_until = NULL,
    last_error   = $2,
    updated_at   = $3
WHERE id = $1::uuid;
