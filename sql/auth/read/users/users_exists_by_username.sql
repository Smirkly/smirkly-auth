SELECT EXISTS (
    SELECT 1
    FROM users
    WHERE username = $1
      AND deleted_at IS NULL
);