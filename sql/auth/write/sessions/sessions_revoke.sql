UPDATE sessions
SET revoked_at = NOW()
WHERE id = $1::uuid
  AND revoked_at IS NULL;