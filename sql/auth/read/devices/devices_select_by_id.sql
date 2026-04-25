SELECT
    id::text AS id,
    user_id::text AS user_id,
    device_type::text AS device_type,
    device_name,
    os_version,
    app_version,
    fingerprint,
    created_at,
    last_seen_at
FROM devices
WHERE id = $1::uuid
LIMIT 1;