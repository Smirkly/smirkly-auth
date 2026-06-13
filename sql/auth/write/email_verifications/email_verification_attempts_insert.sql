INSERT INTO email_verification_attempts (email, user_id, ip, user_agent, attempted_at)
VALUES ($1, NULLIF($2, '')::uuid, NULLIF($3, '')::inet, $4, $5);
