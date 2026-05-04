# Start via `make test-debug` or `make test-release`


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
