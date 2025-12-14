CREATE TABLE devices
(
    id           UUID PRIMARY KEY          DEFAULT gen_random_uuid(),
    user_id      UUID             NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_type  device_type_enum NOT NULL,
    device_name  TEXT,
    os_version   TEXT,
    app_version  TEXT,
    fingerprint  TEXT,
    created_at   TIMESTAMPTZ      NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ
);