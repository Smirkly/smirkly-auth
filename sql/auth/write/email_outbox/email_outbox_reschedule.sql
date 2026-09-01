UPDATE email_outbox
SET
    status          = 'pending',
    next_attempt_at = $3,
    locked_until    = NULL,
    lease_id        = NULL,
    last_error      = $4,
    updated_at      = $5
WHERE id = $1::uuid
  AND lease_id = $2::uuid
  AND status = 'processing'
RETURNING id::text AS id;
