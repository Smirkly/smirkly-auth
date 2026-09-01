SELECT pg_advisory_xact_lock(hashtextextended(lock_key, 0))
FROM (
    SELECT DISTINCT lock_key
    FROM unnest(ARRAY[
        'auth:password-reset:email:' || lower($1::text),
        CASE
            WHEN NULLIF($2::text, '') IS NOT NULL
                THEN 'auth:password-reset:user:' || $2::text
        END,
        CASE
            WHEN NULLIF($3::text, '') IS NOT NULL
                THEN 'auth:password-reset:ip:' || host(NULLIF($3::text, '')::inet)
        END
    ]) AS keys(lock_key)
    WHERE lock_key IS NOT NULL
) AS scopes
ORDER BY lock_key;
