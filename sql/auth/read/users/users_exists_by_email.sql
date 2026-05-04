SELECT EXISTS(
    SELECT 1
    FROM users
    WHERE lower(email) = lower($1)
      AND deleted_at IS NULL
);
