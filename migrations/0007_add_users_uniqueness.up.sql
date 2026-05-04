CREATE UNIQUE INDEX IF NOT EXISTS users_username_uniq
    ON users (lower(username))
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS users_email_uniq
    ON users (lower(email))
    WHERE email IS NOT NULL
      AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS users_phone_uniq
    ON users (phone)
    WHERE phone IS NOT NULL
      AND deleted_at IS NULL;
