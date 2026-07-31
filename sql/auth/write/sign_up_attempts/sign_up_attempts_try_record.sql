WITH counter AS MATERIALIZED (
    SELECT COUNT(*)::bigint AS ip_attempts
    FROM sign_up_attempts
    WHERE ip = $1::inet
      AND attempted_at >= $3
)
INSERT INTO sign_up_attempts (
    ip,
    attempted_at
)
SELECT
    $1::inet,
    $2
FROM counter
WHERE $4::bigint = 0 OR ip_attempts < $4
RETURNING id::text AS id;
