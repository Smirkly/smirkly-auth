UPDATE users
SET is_email_verified = $2
WHERE id = $1::uuid
  AND deleted_at IS NULL;