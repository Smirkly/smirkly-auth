INSERT INTO sessions (
    user_id,
    device_id,
    refresh_token_hash,
    ip,
    user_agent,
    expires_at,
    token_family_id,
    replaced_by_session_id,
    last_used_at
)
VALUES (
           $1::uuid,
           $2::uuid,
           $3,
           NULLIF($4, '')::inet,
           $5,
           $6,
           $7::uuid,
           $8::uuid,
           NOW()
       )
RETURNING
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
    replaced_by_session_id::text AS replaced_by_session_id;