INSERT INTO email_outbox(to_email, template, payload, correlation_id)
VALUES ($1, $2, $3::jsonb, $4);
