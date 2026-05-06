UPDATE sessions
SET revoked_at = NOW()
WHERE id = $1::uuid
  AND user_id = $2::uuid
  AND revoked_at IS NULL
RETURNING id::text AS id;
