INSERT INTO email_verifications (user_id, code_hash, expires_at, ip, user_agent)
VALUES ($1::uuid, $2, $3, NULLIF($4, '')::inet, $5)
RETURNING
    id::text AS id,
    user_id::text AS user_id,
    code_hash,
    created_at,
    expires_at,
    used_at,
    attempts,
    last_attempt_at,
    ip::text AS ip,
    user_agent;