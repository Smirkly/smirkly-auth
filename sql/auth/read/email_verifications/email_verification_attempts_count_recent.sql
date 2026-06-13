SELECT
    COUNT(*) FILTER (WHERE lower(email) = lower($1))::bigint AS email_attempts,
    COUNT(*) FILTER (WHERE user_id = NULLIF($2, '')::uuid)::bigint AS user_attempts,
    COUNT(*) FILTER (WHERE ip = NULLIF($3, '')::inet)::bigint AS ip_attempts
FROM email_verification_attempts
WHERE attempted_at >= $4
  AND (
    lower(email) = lower($1)
        OR user_id = NULLIF($2, '')::uuid
        OR ip = NULLIF($3, '')::inet
    );
