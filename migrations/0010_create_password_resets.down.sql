DROP INDEX IF EXISTS password_reset_attempts_ip_idx;
DROP INDEX IF EXISTS password_reset_attempts_user_idx;
DROP INDEX IF EXISTS password_reset_attempts_email_idx;
DROP TABLE IF EXISTS password_reset_attempts;

DROP INDEX IF EXISTS password_resets_cleanup_idx;
DROP INDEX IF EXISTS password_resets_one_active_per_user;
DROP INDEX IF EXISTS password_resets_active_idx;
DROP TABLE IF EXISTS password_resets;
