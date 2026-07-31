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
