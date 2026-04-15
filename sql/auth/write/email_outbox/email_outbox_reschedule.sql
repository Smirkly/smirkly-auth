UPDATE email_outbox
SET
    status          = 'pending',
    next_attempt_at = $2,
    locked_until    = $3,
    last_error      = $4,
    updated_at      = $5
WHERE id = $1::uuid;
