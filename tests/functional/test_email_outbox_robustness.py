from datetime import datetime, timedelta, timezone
import json
import uuid


CLAIM_SQL = """
WITH candidates AS (
    SELECT id
    FROM email_outbox
    WHERE
        status IN ('pending', 'processing')
      AND next_attempt_at <= %s
      AND attempts < %s
      AND (locked_until IS NULL OR locked_until <= %s)
    ORDER BY next_attempt_at ASC, created_at ASC
    LIMIT %s
        FOR UPDATE SKIP LOCKED
)
UPDATE email_outbox e
SET
    status       = 'processing',
    locked_until = %s,
    lease_id     = gen_random_uuid(),
    attempts     = e.attempts + 1,
    updated_at   = %s,
    last_error   = NULL
FROM candidates c
WHERE e.id = c.id
RETURNING
    e.id::text,
    e.lease_id::text,
    e.status,
    e.attempts,
    e.next_attempt_at,
    e.locked_until
"""


def _cursor(pgsql):
    return pgsql["auth"].cursor()


def _insert_outbox_job(cursor, *, now, attempts=0, status="pending"):
    correlation_id = f"outbox-test-{uuid.uuid4()}"
    cursor.execute(
        """
        INSERT INTO email_outbox(
            to_email, template, payload, correlation_id, status, attempts,
            next_attempt_at, locked_until, created_at, updated_at
        )
        VALUES (
            %s, 'verification_code', %s::jsonb, %s, %s, %s,
            %s, NULL, %s, %s
        )
        RETURNING id::text
        """,
        (
            f"{correlation_id}@example.com",
            json.dumps({"code": "123456", "locale": "ru"}),
            correlation_id,
            status,
            attempts,
            now,
            now,
            now,
        ),
    )
    return cursor.fetchone()[0]


def _claim(cursor, *, now, batch_size=10, stuck_timeout=timedelta(minutes=5), max_attempts=3):
    locked_until = now + stuck_timeout
    cursor.execute(
        CLAIM_SQL,
        (now, max_attempts, now, batch_size, locked_until, now),
    )
    columns = [column.name for column in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def test_processing_job_is_reclaimed_after_stuck_timeout(pgsql):
    cursor = _cursor(pgsql)
    now = datetime.now(timezone.utc)
    job_id = _insert_outbox_job(cursor, now=now)

    first_claim = _claim(cursor, now=now, stuck_timeout=timedelta(minutes=5))
    assert [job["id"] for job in first_claim] == [job_id]
    assert first_claim[0]["status"] == "processing"
    assert first_claim[0]["attempts"] == 1

    before_timeout = _claim(
        cursor,
        now=now + timedelta(minutes=1),
        stuck_timeout=timedelta(minutes=5),
    )
    assert before_timeout == []

    after_timeout = _claim(
        cursor,
        now=now + timedelta(minutes=6),
        stuck_timeout=timedelta(minutes=5),
    )
    assert [job["id"] for job in after_timeout] == [job_id]
    assert after_timeout[0]["attempts"] == 2


def test_claim_batch_does_not_claim_same_job_twice(pgsql):
    cursor = _cursor(pgsql)
    now = datetime.now(timezone.utc)
    first_id = _insert_outbox_job(cursor, now=now)
    second_id = _insert_outbox_job(cursor, now=now + timedelta(milliseconds=1))

    first_claim = _claim(cursor, now=now + timedelta(seconds=1), batch_size=1)
    second_claim = _claim(cursor, now=now + timedelta(seconds=1), batch_size=2)

    assert [job["id"] for job in first_claim] == [first_id]
    assert [job["id"] for job in second_claim] == [second_id]


def test_temporary_failure_reschedule_waits_until_next_attempt(pgsql):
    cursor = _cursor(pgsql)
    now = datetime.now(timezone.utc)
    job_id = _insert_outbox_job(cursor, now=now)

    claim = _claim(cursor, now=now)
    assert [job["id"] for job in claim] == [job_id]

    next_attempt_at = now + timedelta(seconds=2)
    cursor.execute(
        """
        UPDATE email_outbox
        SET status = 'pending', next_attempt_at = %s, locked_until = NULL,
            lease_id = NULL, last_error = %s, updated_at = %s
        WHERE id = %s::uuid
          AND lease_id = %s::uuid
        """,
        (
            next_attempt_at,
            "temporary smtp timeout",
            now,
            job_id,
            claim[0]["lease_id"],
        ),
    )

    before_retry = _claim(cursor, now=now + timedelta(seconds=1))
    assert before_retry == []

    retry_claim = _claim(cursor, now=now + timedelta(seconds=3))
    assert [job["id"] for job in retry_claim] == [job_id]
    assert retry_claim[0]["attempts"] == 2


def test_permanent_or_exhausted_failure_is_not_retried(pgsql):
    cursor = _cursor(pgsql)
    now = datetime.now(timezone.utc)
    job_id = _insert_outbox_job(cursor, now=now, attempts=2)

    claim = _claim(cursor, now=now, max_attempts=3)
    assert [job["id"] for job in claim] == [job_id]
    assert claim[0]["attempts"] == 3

    cursor.execute(
        """
        UPDATE email_outbox
        SET status = 'dead', locked_until = NULL, lease_id = NULL,
            last_error = %s, updated_at = %s
        WHERE id = %s::uuid
          AND lease_id = %s::uuid
        """,
        (
            "permanent smtp auth failure",
            now,
            job_id,
            claim[0]["lease_id"],
        ),
    )

    retry_claim = _claim(cursor, now=now + timedelta(hours=1), max_attempts=3)
    assert retry_claim == []

    cursor.execute(
        "SELECT status, last_error FROM email_outbox WHERE id = %s::uuid",
        (job_id,),
    )
    status, last_error = cursor.fetchone()
    assert status == "dead"
    assert last_error == "permanent smtp auth failure"


def test_stale_worker_cannot_persist_result_after_reclaim(pgsql):
    cursor = _cursor(pgsql)
    now = datetime.now(timezone.utc)
    job_id = _insert_outbox_job(cursor, now=now)

    first_claim = _claim(
        cursor,
        now=now,
        stuck_timeout=timedelta(seconds=1),
    )
    stale_lease_id = first_claim[0]["lease_id"]

    second_claim = _claim(
        cursor,
        now=now + timedelta(seconds=2),
        stuck_timeout=timedelta(minutes=5),
    )
    current_lease_id = second_claim[0]["lease_id"]
    assert current_lease_id != stale_lease_id

    cursor.execute(
        """
        UPDATE email_outbox
        SET status = 'sent', payload = '{}'::jsonb, locked_until = NULL,
            lease_id = NULL, updated_at = %s
        WHERE id = %s::uuid
          AND lease_id = %s::uuid
          AND status = 'processing'
        """,
        (now + timedelta(seconds=3), job_id, stale_lease_id),
    )
    assert cursor.rowcount == 0

    cursor.execute(
        """
        UPDATE email_outbox
        SET status = 'sent', payload = '{}'::jsonb, locked_until = NULL,
            lease_id = NULL, updated_at = %s
        WHERE id = %s::uuid
          AND lease_id = %s::uuid
          AND status = 'processing'
        """,
        (now + timedelta(seconds=3), job_id, current_lease_id),
    )
    assert cursor.rowcount == 1
