UPDATE users
SET is_phone_verified = $2
WHERE id = $1
  AND deleted_at IS NULL;