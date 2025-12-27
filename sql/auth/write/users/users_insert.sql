INSERT INTO users (username, email, phone, password_hash)
VALUES ($1, $2, $3, $4)
RETURNING
    id::text,
    username,
    email,
    phone,
    password_hash,
    is_email_verified,
    is_phone_verified;