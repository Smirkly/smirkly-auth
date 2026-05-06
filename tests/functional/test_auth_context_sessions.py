import uuid


async def _create_signed_in_user(service_client):
    suffix = uuid.uuid4().hex[:12]
    username = f"session_user_{suffix}"
    email = f"session-{suffix}@example.com"
    password = "StrongPass123!"

    sign_up_response = await service_client.post(
        "/auth/v0/sign-up",
        json={
            "username": username,
            "email": email,
            "password": password,
        },
    )
    assert sign_up_response.status == 201

    sign_in_response = await service_client.post(
        "/auth/v0/sign-in",
        json={
            "username": username,
            "password": password,
        },
    )
    assert sign_in_response.status == 200

    body = sign_in_response.json()
    return {
        "username": username,
        "access_token": body["tokens"]["access_token"],
        "session_id": body["session_id"],
        "refresh_cookie": sign_in_response.headers["Set-Cookie"].split(";", 1)[0],
    }


async def test_me_returns_current_user(service_client):
    account = await _create_signed_in_user(service_client)

    response = await service_client.get(
        "/auth/v0/me",
        headers={"Authorization": f"Bearer {account['access_token']}"},
    )

    assert response.status == 200
    body = response.json()
    assert body["user"]["username"] == account["username"]
    assert body["session_id"] == account["session_id"]


async def test_sessions_list_and_revoke_current_session(service_client):
    account = await _create_signed_in_user(service_client)
    headers = {"Authorization": f"Bearer {account['access_token']}"}

    sessions_response = await service_client.get(
        "/auth/v0/sessions",
        headers=headers,
    )
    assert sessions_response.status == 200

    sessions = sessions_response.json()["sessions"]
    current_session = next(
        session for session in sessions if session["id"] == account["session_id"]
    )
    assert current_session["current"] is True

    revoke_response = await service_client.delete(
        f"/auth/v0/sessions/{account['session_id']}",
        headers=headers,
    )
    assert revoke_response.status == 204

    me_after_revoke_response = await service_client.get(
        "/auth/v0/me",
        headers=headers,
    )
    assert me_after_revoke_response.status == 401


async def test_refresh_rotates_session_and_detects_reuse(service_client):
    account = await _create_signed_in_user(service_client)

    refresh_response = await service_client.post(
        "/auth/v0/refresh",
        headers={"Cookie": account["refresh_cookie"]},
    )
    assert refresh_response.status == 200

    refreshed = refresh_response.json()
    new_access_token = refreshed["tokens"]["access_token"]
    new_session_id = refreshed["session_id"]

    assert new_session_id != account["session_id"]
    assert refresh_response.headers["Set-Cookie"].startswith("refresh_token=")

    old_access_response = await service_client.get(
        "/auth/v0/me",
        headers={"Authorization": f"Bearer {account['access_token']}"},
    )
    assert old_access_response.status == 401

    new_access_response = await service_client.get(
        "/auth/v0/me",
        headers={"Authorization": f"Bearer {new_access_token}"},
    )
    assert new_access_response.status == 200
    assert new_access_response.json()["session_id"] == new_session_id

    reuse_response = await service_client.post(
        "/auth/v0/refresh",
        headers={"Cookie": account["refresh_cookie"]},
    )
    assert reuse_response.status == 401

    new_access_after_reuse_response = await service_client.get(
        "/auth/v0/me",
        headers={"Authorization": f"Bearer {new_access_token}"},
    )
    assert new_access_after_reuse_response.status == 401
