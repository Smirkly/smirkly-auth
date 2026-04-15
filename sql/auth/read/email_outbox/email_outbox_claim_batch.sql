WITH candidates AS (
    SELECT id
    FROM email_outbox
    WHERE
        status IN ('pending', 'processing')
      AND next_attempt_at <= $2
      AND attempts < $4
      AND (
        locked_until IS NULL
            OR locked_until <= $2
        )
    ORDER BY next_attempt_at ASC, created_at ASC
    LIMIT $1
        FOR UPDATE SKIP LOCKED
)
UPDATE email_outbox e
SET
    status       = 'processing',
    locked_until = $3,
    attempts     = e.attempts + 1,
    updated_at   = $2,
    last_error   = NULL
FROM candidates c
WHERE e.id = c.id
RETURNING
    e.id::text AS id,
    e.to_email,
    e.template,
    e.payload,
    e.correlation_id,
    e.status,
    e.attempts,
    e.next_attempt_at,
    e.locked_until,
    e.last_error,
    e.created_at,
    e.updated_at;
