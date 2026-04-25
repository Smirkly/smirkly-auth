UPDATE sessions
SET last_used_at = GREATEST(COALESCE(last_used_at, $2), $2)
WHERE id = $1::uuid
  AND revoked_at IS NULL;