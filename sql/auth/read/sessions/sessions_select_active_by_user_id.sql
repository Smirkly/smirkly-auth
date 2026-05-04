SELECT
    id::text AS id,
    user_id::text AS user_id,
    device_id::text AS device_id,
    refresh_token_hash,
    ip::text AS ip,
    user_agent,
    created_at,
    last_used_at,
    expires_at,
    revoked_at,
    token_family_id::text AS token_family_id,
    replaced_by_session_id::text AS replaced_by_session_id
FROM sessions
WHERE user_id = $1::uuid
  AND revoked_at IS NULL
  AND expires_at > NOW()
ORDER BY last_used_at DESC NULLS LAST, created_at DESC;
