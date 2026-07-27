async def test_liveness_on_monitor_listener(monitor_client):
    response = await monitor_client.get("/health/live")

    assert response.status == 200
    assert response.json() == {"status": "ok"}


async def test_readiness_checks_dependencies_on_monitor_listener(monitor_client):
    response = await monitor_client.get("/health/ready")

    assert response.status == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"]["postgres"]["ok"] is True
    assert body["checks"]["migrations"]["ok"] is True
    assert body["checks"]["migrations"]["details"]["expected_version"] == 11
    assert body["checks"]["migrations"]["details"]["schema_ready"] is True
    assert body["checks"]["dynamic_config"]["ok"] is True


async def test_health_is_not_exposed_on_public_listener(service_client):
    live_response = await service_client.get("/health/live")
    ready_response = await service_client.get("/health/ready")

    assert live_response.status == 404
    assert ready_response.status == 404
