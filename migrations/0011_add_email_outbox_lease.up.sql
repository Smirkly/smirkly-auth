ALTER TABLE email_outbox
    ADD COLUMN lease_id UUID;

UPDATE email_outbox
SET
    status = 'pending',
    locked_until = NULL
WHERE status = 'processing';

ALTER TABLE email_outbox
    ADD CONSTRAINT email_outbox_processing_lease_check
        CHECK (
            (
                status = 'processing'
                AND lease_id IS NOT NULL
                AND locked_until IS NOT NULL
            )
            OR
            (
                status <> 'processing'
                AND lease_id IS NULL
            )
        );
