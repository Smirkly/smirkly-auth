UPDATE users
SET deleted_at = now()
WHERE id = $1::uuid
  AND deleted_at IS NULL;