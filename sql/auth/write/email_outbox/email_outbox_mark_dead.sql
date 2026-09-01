UPDATE email_outbox
SET
    status       = 'dead',
    payload      = '{}'::jsonb,
    locked_until = NULL,
    lease_id     = NULL,
    last_error   = $3,
    updated_at   = $4
WHERE id = $1::uuid
  AND lease_id = $2::uuid
  AND status = 'processing'
RETURNING id::text AS id;
