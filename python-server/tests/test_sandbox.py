from uuid import uuid4

from app.sandbox import sandbox_status
from app.database import insert_investigation_events, list_investigation_events

def test_sandbox_is_fail_closed_without_external_configuration(monkeypatch):
    monkeypatch.delenv("SANDBOX_API_URL", raising=False)
    monkeypatch.delenv("SANDBOX_HEALTH_URL", raising=False)

    result = sandbox_status()

    assert result["configured"] is False
    assert result["executionAvailable"] is False
    assert result["mode"] == "disabled"

def test_sandbox_requires_https_external_urls(monkeypatch):
    monkeypatch.setenv("SANDBOX_API_URL", "http://sandbox.internal/api")
    monkeypatch.setenv("SANDBOX_HEALTH_URL", "https://sandbox.internal/health")

    result = sandbox_status()

    assert result["configured"] is False
    assert result["executionAvailable"] is False


def test_investigation_events_are_idempotent_and_ordered():
    suffix = uuid4().hex
    artifact_id = f"timeline-test-artifact-{suffix}"
    events = [
        {"id": f"timeline-event-1-{suffix}", "timestamp": "2026-09-17T10:00:00Z", "message": "Started", "type": "info"},
        {"id": f"timeline-event-2-{suffix}", "timestamp": "2026-09-17T10:01:00Z", "message": "Completed", "type": "success"},
    ]

    assert insert_investigation_events(artifact_id, events, "test-user") == 2
    assert insert_investigation_events(artifact_id, events, "test-user") == 0
    assert [event["id"] for event in list_investigation_events(artifact_id)] == [f"timeline-event-2-{suffix}", f"timeline-event-1-{suffix}"]