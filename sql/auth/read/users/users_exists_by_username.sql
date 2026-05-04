SELECT EXISTS (
    SELECT 1
    FROM users
    WHERE lower(username) = lower($1)
      AND deleted_at IS NULL
);
