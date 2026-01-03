INSERT INTO email_outbox(to_email, template, payload, correlation_id)
VALUES ($1, 'verification_code',
        jsonb_build_object('code', $2, 'locale', $3),
        $4);