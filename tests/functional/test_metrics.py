import uuid


async def test_auth_metrics_are_exposed(monitor_client):
    metrics = await monitor_client.metrics(prefix="auth.email-outbox")

    for result in ("sent", "retry_scheduled", "dead", "lease_lost"):
        assert metrics.value_at(
            "auth.email-outbox.deliveries.total",
            labels={"result": result},
        ) == 0

    for stage in ("claim", "persist"):
        assert metrics.value_at(
            "auth.email-outbox.errors.total",
            labels={"stage": stage},
        ) == 0

    duration = await monitor_client.single_metric(
        "auth.email-outbox.processing-duration-seconds",
    )
    assert duration.labels == {}


async def test_password_hashing_uses_dedicated_task_processor(
        service_client, monitor_client
):
    labels = {"task_processor": "password-hashing-task-processor"}
    before = await monitor_client.metrics(prefix="engine.task-processors")
    created_before = before.value_at(
        "engine.task-processors.tasks.created",
        labels=labels,
    )

    unique = uuid.uuid4().hex
    response = await service_client.post(
        "/auth/v0/sign-up",
        json={
            "username": f"hash_{unique[:16]}",
            "email": f"hash-{unique}@example.com",
            "password": "StrongPass123!",
        },
    )
    assert response.status == 201

    after = await monitor_client.metrics(prefix="engine.task-processors")
    assert after.value_at(
        "engine.task-processors.worker-threads",
        labels=labels,
    ) == 1
    assert after.value_at(
        "engine.task-processors.tasks.created",
        labels=labels,
    ) >= created_before + 2
