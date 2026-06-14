UPDATE email_verifications
SET used_at = $2
WHERE user_id = $1::uuid
  AND used_at IS NULL;
