import asyncio
import uuid


def _assert_error(response, status, code):
    assert response.status == status
    body = response.json()
    assert body["code"] == code
    assert isinstance(body["message"], str)
    assert body["message"]


async def _sign_up_user(service_client, *, verified, pgsql):
    suffix = uuid.uuid4().hex[:12]
    username = f"auth_contract_{suffix}"
    email = f"auth-contract-{suffix}@example.com"
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

    if verified:
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


async def test_sign_in_rejects_unverified_email_with_error_contract(
    service_client,
    pgsql,
):
    account = await _sign_up_user(service_client, verified=False, pgsql=pgsql)

    response = await service_client.post(
        "/auth/v0/sign-in",
        json={
            "username": account["username"],
            "password": account["password"],
        },
    )

    _assert_error(response, 403, "auth.email_not_verified")


async def test_concurrent_sign_ups_cannot_bypass_rate_limit(service_client):
    async def attempt(index):
        suffix = uuid.uuid4().hex[:12]
        return await service_client.post(
            "/auth/v0/sign-up",
            json={
                "username": f"signup_limit_{index}_{suffix}",
                "email": f"signup-limit-{index}-{suffix}@example.com",
                "password": "StrongPass123!",
            },
        )

    responses = await asyncio.gather(*(attempt(index) for index in range(8)))
    statuses = [response.status for response in responses]

    assert statuses.count(201) == 2
    assert statuses.count(429) == 6
    for response in responses:
        if response.status == 429:
            _assert_error(response, 429, "auth.sign_up.too_many_attempts")


async def test_sign_in_invalid_password_is_rate_limited(service_client, pgsql):
    account = await _sign_up_user(service_client, verified=True, pgsql=pgsql)

    for _ in range(2):
        response = await service_client.post(
            "/auth/v0/sign-in",
            json={
                "username": account["username"],
                "password": "WrongPass123!",
            },
        )
        _assert_error(response, 401, "auth.invalid_credentials")

    limited_response = await service_client.post(
        "/auth/v0/sign-in",
        json={
            "username": account["username"],
            "password": "WrongPass123!",
        },
    )

    _assert_error(limited_response, 429, "auth.sign_in.too_many_attempts")


async def test_concurrent_sign_in_failures_cannot_bypass_rate_limit(
    service_client,
    pgsql,
):
    account = await _sign_up_user(service_client, verified=True, pgsql=pgsql)

    async def attempt():
        return await service_client.post(
            "/auth/v0/sign-in",
            json={
                "username": account["username"],
                "password": "WrongPass123!",
            },
        )

    responses = await asyncio.gather(*(attempt() for _ in range(8)))
    statuses = [response.status for response in responses]

    assert statuses.count(401) == 2
    assert statuses.count(429) == 6


async def test_verify_email_invalid_code_is_rate_limited(service_client):
    suffix = uuid.uuid4().hex[:12]
    email = f"verify-limit-{suffix}@example.com"

    sign_up_response = await service_client.post(
        "/auth/v0/sign-up",
        json={
            "username": f"verify_limit_{suffix}",
            "email": email,
            "password": "StrongPass123!",
        },
    )
    assert sign_up_response.status == 201

    for _ in range(2):
        response = await service_client.post(
            "/auth/v0/verify-email",
            json={
                "email": email,
                "code": "000000",
            },
        )
        _assert_error(response, 400, "auth.verify_email.invalid_code")

    limited_response = await service_client.post(
        "/auth/v0/verify-email",
        json={
            "email": email,
            "code": "000000",
        },
    )

    _assert_error(limited_response, 429, "auth.verify_email.too_many_attempts")


async def test_resend_email_verification_is_rate_limited(service_client):
    suffix = uuid.uuid4().hex[:12]
    email = f"resend-limit-{suffix}@example.com"

    sign_up_response = await service_client.post(
        "/auth/v0/sign-up",
        json={
            "username": f"resend_limit_{suffix}",
            "email": email,
            "password": "StrongPass123!",
        },
    )
    assert sign_up_response.status == 201

    for _ in range(2):
        response = await service_client.post(
            "/auth/v0/verify-email/resend",
            json={"email": email},
        )
        assert response.status == 204

    limited_response = await service_client.post(
        "/auth/v0/verify-email/resend",
        json={"email": email},
    )

    _assert_error(
        limited_response,
        429,
        "auth.resend_email_verification.too_many_attempts",
    )


async def test_wrong_json_field_types_use_stable_error_contract(service_client):
    cases = [
        (
            "/auth/v0/sign-up",
            {
                "username": 42,
                "email": "wrong-type@example.com",
                "password": "StrongPass123!",
            },
            "sign_up.validation_failed",
        ),
        (
            "/auth/v0/sign-in",
            {
                "username": "wrong_type_user",
                "password": 42,
            },
            "auth.sign_in.validation_failed",
        ),
        (
            "/auth/v0/verify-email",
            {
                "email": 42,
                "code": "123456",
            },
            "auth.verify_email.validation_failed",
        ),
        (
            "/auth/v0/verify-email/resend",
            {"email": ["wrong-type@example.com"]},
            "auth.resend_email_verification.validation_failed",
        ),
        (
            "/auth/v0/password-reset/request",
            {"email": False},
            "auth.password_reset.validation_failed",
        ),
        (
            "/auth/v0/password-reset/confirm",
            {
                "email": "wrong-type@example.com",
                "token": {"value": "not-a-string"},
                "new_password": "NewStrongPass123!",
            },
            "auth.password_reset.validation_failed",
        ),
    ]

    for path, payload, expected_code in cases:
        response = await service_client.post(path, json=payload)
        _assert_error(response, 400, expected_code)
