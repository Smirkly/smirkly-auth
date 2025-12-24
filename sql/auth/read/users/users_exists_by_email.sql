SELECT EXISTS(
    SELECT 1
    FROM users
    WHERE email = $1
      AND deleted_at IS NULL
);