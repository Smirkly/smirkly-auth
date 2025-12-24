INSERT INTO users (username, email, phone, password_hash)
VALUES ($1, $2, $3, $4)
RETURNING
    id,
    username,
    email,
    phone,
    password_hash,
    is_email_verified,
    is_phone_verified,
    created_at,
    password_updated_at,
    deleted_at;