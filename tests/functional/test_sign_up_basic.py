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

    assert response.status == 200

    body = response.json()
    assert body["user"]["username"] == "dima_test"
    assert body["user"]["email"] == "dima@example.com"
    assert body["user"]["is_email_verified"] is False
    assert body["user"]["is_phone_verified"] is False
