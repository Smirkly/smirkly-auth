UPDATE email_verifications
SET used_at = $2
WHERE id = $1::uuid
  AND used_at IS NULL
  AND expires_at > $2
  AND attempts < $3
RETURNING id::text AS id;
