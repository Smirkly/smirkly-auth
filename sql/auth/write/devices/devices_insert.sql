INSERT INTO devices (
    user_id,
    device_type,
    device_name,
    os_version,
    app_version,
    fingerprint,
    last_seen_at
)
VALUES (
           $1::uuid,
           $2::device_type_enum,
           $3,
           $4,
           $5,
           $6,
           NOW()
       )
RETURNING
    id::text AS id,
    user_id::text AS user_id,
    device_type::text AS device_type,
    device_name,
    os_version,
    app_version,
    fingerprint,
    created_at,
    last_seen_at;