SELECT EXISTS(
    SELECT 1
    FROM users
    WHERE phone = $1
      AND deleted_at IS NULL
);