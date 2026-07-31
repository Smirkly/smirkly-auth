WITH counters AS MATERIALIZED (
    SELECT
        COUNT(*) FILTER (
            WHERE lower(email) = lower($1)
        )::bigint AS email_attempts,
        COUNT(*) FILTER (
            WHERE user_id = NULLIF($2, '')::uuid
        )::bigint AS user_attempts,
        COUNT(*) FILTER (
            WHERE ip = NULLIF($3, '')::inet
        )::bigint AS ip_attempts
    FROM email_verification_attempts
    WHERE attempted_at >= $6
      AND (
        lower(email) = lower($1)
            OR user_id = NULLIF($2, '')::uuid
            OR ip = NULLIF($3, '')::inet
        )
)
INSERT INTO email_verification_attempts (
    email,
    user_id,
    ip,
    user_agent,
    attempted_at
)
SELECT
    $1,
    NULLIF($2, '')::uuid,
    NULLIF($3, '')::inet,
    $4,
    $5
FROM counters
WHERE ($7::bigint = 0 OR email_attempts < $7)
  AND ($8::bigint = 0 OR NULLIF($2, '') IS NULL OR user_attempts < $8)
  AND ($9::bigint = 0 OR NULLIF($3, '') IS NULL OR ip_attempts < $9)
RETURNING id::text AS id;
