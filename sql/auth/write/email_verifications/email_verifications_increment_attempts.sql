UPDATE email_verifications
SET attempts = attempts + 1,
    last_attempt_at = $2
WHERE id = $1::uuid
  AND used_at IS NULL;
