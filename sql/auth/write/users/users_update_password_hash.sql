UPDATE users
SET password_hash       = $2,
    password_updated_at = now()
WHERE id = $1::uuid
  AND deleted_at IS NULL;