DROP INDEX IF EXISTS email_verifications_one_active_per_user;
DROP INDEX IF EXISTS email_verifications_active_idx;
DROP INDEX IF EXISTS email_verifications_cleanup_idx;

DROP TABLE IF EXISTS email_verifications;
