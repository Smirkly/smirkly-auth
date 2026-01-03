SELECT
    id,
    username,
    email,
    phone,
    password_hash,
    is_email_verified,
    is_phone_verified,
    created_at,
    password_updated_at,
    deleted_at
FROM users
WHERE email = $1
  AND deleted_at IS NULL;