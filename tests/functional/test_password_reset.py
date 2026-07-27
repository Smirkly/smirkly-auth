import asyncio
import uuid


async def _sign_up_verified_user(service_client, pgsql):
    suffix = uuid.uuid4().hex[:12]
    username = f"reset_user_{suffix}"
    email = f"reset-{suffix}@example.com"
    password = "StrongPass123!"

    response = await service_client.post(
        "/auth/v0/sign-up",
        json={
            "username": username,
            "email": email,
            "password": password,
        },
    )
    assert response.status == 201

    cursor = pgsql["auth"].cursor()
    cursor.execute(
        "UPDATE users SET is_email_verified = TRUE WHERE username = %s",
        (username,),
    )

    return {
        "username": username,
        "email": email,
        "password": password,
    }


async def _sign_in(service_client, *, username, password):
    return await service_client.post(
        "/auth/v0/sign-in",
        json={
            "username": username,
            "password": password,
        },
    )


def _latest_reset_token(pgsql, email):
    cursor = pgsql["auth"].cursor()
    cursor.execute(
        """
        SELECT payload->>'token'
        FROM email_outbox
        WHERE to_email = %s AND template = 'password_reset'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (email,),
    )
    row = cursor.fetchone()
    assert row is not None
    return row[0]


async def test_password_reset_request_is_enumeration_safe(service_client, pgsql):
    email = f"missing-reset-{uuid.uuid4().hex[:12]}@example.com"

    response = await service_client.post(
        "/auth/v0/password-reset/request",
        json={"email": email},
    )

    assert response.status == 204

    cursor = pgsql["auth"].cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM email_outbox WHERE to_email = %s",
        (email,),
    )
    assert cursor.fetchone()[0] == 0


async def test_password_reset_confirm_changes_password_and_revokes_sessions(
    service_client,
    pgsql,
):
    account = await _sign_up_verified_user(service_client, pgsql)

    sign_in_response = await _sign_in(
        service_client,
        username=account["username"],
        password=account["password"],
    )
    assert sign_in_response.status == 200
    access_token = sign_in_response.json()["tokens"]["access_token"]

    request_response = await service_client.post(
        "/auth/v0/password-reset/request",
        json={"email": account["email"]},
    )
    assert request_response.status == 204

    reset_token = _latest_reset_token(pgsql, account["email"])
    new_password = "NewStrongPass123!"

    confirm_response = await service_client.post(
        "/auth/v0/password-reset/confirm",
        json={
            "email": account["email"],
            "token": reset_token,
            "new_password": new_password,
        },
    )
    assert confirm_response.status == 204

    me_response = await service_client.get(
        "/auth/v0/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_response.status == 401

    old_password_response = await _sign_in(
        service_client,
        username=account["username"],
        password=account["password"],
    )
    assert old_password_response.status == 401

    new_password_response = await _sign_in(
        service_client,
        username=account["username"],
        password=new_password,
    )
    assert new_password_response.status == 200


async def test_password_reset_invalid_token_consumes_attempts(service_client, pgsql):
    account = await _sign_up_verified_user(service_client, pgsql)

    request_response = await service_client.post(
        "/auth/v0/password-reset/request",
        json={"email": account["email"]},
    )
    assert request_response.status == 204

    for _ in range(2):
        response = await service_client.post(
            "/auth/v0/password-reset/confirm",
            json={
                "email": account["email"],
                "token": "wrong-token",
                "new_password": "NewStrongPass123!",
            },
        )
        assert response.status == 400
        assert response.json()["code"] == "auth.password_reset.invalid_token"

    expired_response = await service_client.post(
        "/auth/v0/password-reset/confirm",
        json={
            "email": account["email"],
            "token": _latest_reset_token(pgsql, account["email"]),
            "new_password": "NewStrongPass123!",
        },
    )
    assert expired_response.status == 410
    assert expired_response.json()["code"] == "auth.password_reset.expired"


async def test_password_reset_request_is_rate_limited(service_client):
    email = f"reset-limit-{uuid.uuid4().hex[:12]}@example.com"

    for _ in range(4):
        response = await service_client.post(
            "/auth/v0/password-reset/request",
            json={"email": email},
        )
        assert response.status == 204

    limited_response = await service_client.post(
        "/auth/v0/password-reset/request",
        json={"email": email},
    )

    assert limited_response.status == 429
    assert limited_response.json()["code"] == "auth.password_reset.too_many_attempts"


async def test_concurrent_password_reset_requests_are_serialized(
    service_client,
    pgsql,
):
    account = await _sign_up_verified_user(service_client, pgsql)

    async def request_reset():
        return await service_client.post(
            "/auth/v0/password-reset/request",
            json={"email": account["email"]},
        )

    responses = await asyncio.gather(*(request_reset() for _ in range(8)))
    statuses = [response.status for response in responses]

    assert statuses.count(204) == 4
    assert statuses.count(429) == 4

    cursor = pgsql["auth"].cursor()
    cursor.execute(
        """
        SELECT
            COUNT(*),
            COUNT(*) FILTER (WHERE used_at IS NULL)
        FROM password_resets
        WHERE user_id = (
            SELECT id FROM users WHERE email = %s
        )
        """,
        (account["email"],),
    )
    total_resets, active_resets = cursor.fetchone()
    assert total_resets == 4
    assert active_resets == 1


async def test_password_reset_token_is_consumed_once_under_concurrency(
    service_client,
    pgsql,
):
    account = await _sign_up_verified_user(service_client, pgsql)
    request_response = await service_client.post(
        "/auth/v0/password-reset/request",
        json={"email": account["email"]},
    )
    assert request_response.status == 204

    reset_token = _latest_reset_token(pgsql, account["email"])
    new_password = "ConcurrentPass123!"

    async def confirm_reset():
        return await service_client.post(
            "/auth/v0/password-reset/confirm",
            json={
                "email": account["email"],
                "token": reset_token,
                "new_password": new_password,
            },
        )

    responses = await asyncio.gather(confirm_reset(), confirm_reset())
    statuses = [response.status for response in responses]

    assert statuses.count(204) == 1
    assert len([status for status in statuses if status in (400, 410)]) == 1

    sign_in_response = await _sign_in(
        service_client,
        username=account["username"],
        password=new_password,
    )
    assert sign_in_response.status == 200
