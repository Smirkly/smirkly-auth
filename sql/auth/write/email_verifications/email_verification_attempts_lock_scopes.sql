SELECT pg_advisory_xact_lock(hashtextextended(lock_key, 0))
FROM (
    SELECT DISTINCT lock_key
    FROM unnest(ARRAY[
        'auth:email-verification:email:' || lower($1::text),
        CASE
            WHEN NULLIF($2::text, '') IS NOT NULL
                THEN 'auth:email-verification:user:' || $2::text
        END,
        CASE
            WHEN NULLIF($3::text, '') IS NOT NULL
                THEN 'auth:email-verification:ip:' || host(NULLIF($3::text, '')::inet)
        END
    ]) AS keys(lock_key)
    WHERE lock_key IS NOT NULL
) AS scopes
ORDER BY lock_key;
