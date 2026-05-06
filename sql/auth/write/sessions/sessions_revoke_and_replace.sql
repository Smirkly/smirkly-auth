UPDATE sessions
SET revoked_at = NOW(),
    replaced_by_session_id = $2::uuid
WHERE id = $1::uuid
  AND revoked_at IS NULL
RETURNING id::text AS id;
