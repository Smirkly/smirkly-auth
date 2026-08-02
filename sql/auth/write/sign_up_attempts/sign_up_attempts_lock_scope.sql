SELECT pg_advisory_xact_lock(
    hashtextextended('auth:sign-up:ip:' || host($1::inet), 0)
);
