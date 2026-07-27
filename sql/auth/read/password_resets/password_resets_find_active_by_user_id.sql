SELECT
    id::text AS id,
    user_id::text AS user_id,
    token_hash,
    created_at,
    expires_at,
    used_at,
    attempts,
    last_attempt_at,
    ip::text AS ip,
    user_agent
FROM password_resets
WHERE user_id = $1::uuid
  AND used_at IS NULL
  AND expires_at > $2
  AND attempts < $3
ORDER BY created_at DESC
LIMIT 1;
