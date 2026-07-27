ALTER TABLE email_outbox
    DROP CONSTRAINT IF EXISTS email_outbox_processing_lease_check;

ALTER TABLE email_outbox
    DROP COLUMN IF EXISTS lease_id;
