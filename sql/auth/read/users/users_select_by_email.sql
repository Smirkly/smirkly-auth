SELECT
    id::text            AS id,
    username            AS username,
    email               AS email,
    phone               AS phone,
    password_hash       AS password_hash,
    is_email_verified   AS is_email_verified,
    is_phone_verified   AS is_phone_verified,
    created_at          AS created_at,
    password_updated_at AS password_updated_at,
    deleted_at          AS deleted_at
FROM users
WHERE lower(email) = lower($1)
  AND deleted_at IS NULL;
