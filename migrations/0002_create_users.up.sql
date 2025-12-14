CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users
(
    id                  UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    username            TEXT        NOT NULL,
    email               TEXT,
    phone               TEXT,
    password_hash       TEXT        NOT NULL,
    is_email_verified   BOOLEAN     NOT NULL DEFAULT FALSE,
    is_phone_verified   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    password_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ
);