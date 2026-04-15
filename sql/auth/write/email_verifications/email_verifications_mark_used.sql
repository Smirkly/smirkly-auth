UPDATE email_verifications
SET used_at = $2
WHERE id = $1::uuid
  AND used_at IS NULL;
