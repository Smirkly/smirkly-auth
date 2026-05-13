UPDATE sessions
SET revoked_at = NOW()
WHERE user_id = $1::uuid
  AND revoked_at IS NULL;
