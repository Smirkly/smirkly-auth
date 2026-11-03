# Start via `make test-debug` or `make test-release`


import uuid


async def test_sign_up_basic(service_client):
    payload = {
        "username": "dima_test",
        "email": "dima@example.com",
        "password": "StrongPass123!",
    }

    response = await service_client.post(
        '/auth/v0/sign-up',
        json=payload,
    )

    assert response.status == 201

    body = response.json()
    assert body["user"]["username"] == "dima_test"
    assert body["user"]["email"] == "dima@example.com"
    assert body["user"]["is_email_verified"] is False
    assert body["user"]["is_phone_verified"] is False


async def test_sign_up_code_is_hmac_hashed_and_verifies(service_client, pgsql):
    suffix = uuid.uuid4().hex[:12]
    email = f"verify-{suffix}@example.com"

    sign_up_response = await service_client.post(
        "/auth/v0/sign-up",
        json={
            "username": f"verify_{suffix}",
            "email": email,
            "password": "StrongPass123!",
        },
    )
    assert sign_up_response.status == 201
    user_id = sign_up_response.json()["user"]["id"]

    cursor = pgsql["auth"].cursor()
    cursor.execute(
        """
        SELECT payload->>'code'
        FROM email_outbox
        WHERE to_email = %s AND template = 'verification_code'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (email,),
    )
    code_row = cursor.fetchone()
    assert code_row is not None
    code = code_row[0]

    cursor.execute(
        """
        SELECT code_hash
        FROM email_verifications
        WHERE user_id = %s::uuid AND used_at IS NULL
        """,
        (user_id,),
    )
    hash_row = cursor.fetchone()
    assert hash_row is not None
    assert hash_row[0].startswith("hmac-sha256:v1:")

    verify_response = await service_client.post(
        "/auth/v0/verify-email",
        json={"email": email, "code": code},
    )
    assert verify_response.status == 204

    cursor.execute(
        "SELECT is_email_verified FROM users WHERE id = %s::uuid",
        (user_id,),
    )
    assert cursor.fetchone() == (True,)


async def test_sign_up_duplicate_email_conflict(service_client):
    payload = {
        "username": "duplicate_email_one",
        "email": "duplicate@example.com",
        "password": "StrongPass123!",
    }

    first_response = await service_client.post(
        '/auth/v0/sign-up',
        json=payload,
    )
    assert first_response.status == 201

    second_response = await service_client.post(
        '/auth/v0/sign-up',
        json={
            "username": "duplicate_email_two",
            "email": "DUPLICATE@example.com",
            "password": "StrongPass123!",
        },
    )

    assert second_response.status == 409
    assert second_response.json()["code"] == "sign_up.email_taken"
