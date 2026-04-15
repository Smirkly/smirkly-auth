SELECT id::text        AS id,
       user_id::text   AS user_id,
       code_hash       AS code_hash,
       created_at      AS created_at,
       expires_at      AS expires_at,
       used_at         AS used_at,
       attempts        AS attempts,
       last_attempt_at AS last_attempt_at,
       ip::text        AS ip,
       user_agent      AS user_agent
FROM email_verifications
WHERE user_id = $1::uuid
  AND used_at IS NULL
  AND expires_at > $2
ORDER BY created_at DESC
LIMIT 1;