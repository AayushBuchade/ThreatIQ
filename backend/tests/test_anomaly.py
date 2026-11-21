"""Isolation Forest assessments stay off the stored severity and threat score."""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.app.models.security_event import SecurityEvent
from backend.app.services.anomaly_detector import MIN_TRAINING_EVENTS, MODEL_VERSION


def _ingest(client: TestClient, **overrides) -> dict:
    payload = {
        "event_type": "system.heartbeat",
        "severity": "low",
        "source_ip": "10.1.1.1",
        "message": "routine heartbeat",
    }
    payload.update(overrides)
    response = client.post("/api/v1/events/ingest", json=payload)
    assert response.status_code == 202, response.text
    return response.json()


def _set_times(db_session, stamps: dict[str, datetime]) -> None:
    rows = db_session.execute(select(SecurityEvent)).scalars().all()
    for row in rows:
        if row.event_id in stamps:
            row.created_at = stamps[row.event_id]
            row.updated_at = stamps[row.event_id]
    db_session.commit()


def test_unknown_event_is_not_found(client: TestClient):
    response = client.get("/api/v1/events/tiq-does-not-exist/anomaly")
    assert response.status_code == 404


def test_insufficient_history_does_not_invent_a_detection(client: TestClient, db_session):
    saved = _ingest(client, message="only event")
    before = db_session.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == saved["event_id"])
    ).scalar_one()
    severity = before.severity
    threat_score = before.threat_score

    response = client.get(f"/api/v1/events/{saved['event_id']}/anomaly")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "insufficient_data"
    assert body["evaluated"] is False
    assert body["model_score"] is None
    assert body["feature_evidence"] == []
    assert body["model_version"] == MODEL_VERSION
    assert body["training_events"] < MIN_TRAINING_EVENTS

    after = db_session.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == saved["event_id"])
    ).scalar_one()
    assert after.severity == severity
    assert after.threat_score == threat_score


def test_scores_a_later_event_without_training_on_it(client: TestClient, db_session):
    start = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
    stamps = {}
    baseline_ids = []
    for index in range(40):
        saved = _ingest(client, message=f"heartbeat {index}")
        baseline_ids.append(saved["event_id"])
        stamps[saved["event_id"]] = start + timedelta(hours=index)

    burst_start = datetime(2026, 11, 4, 3, 0, tzinfo=timezone.utc)
    burst_ids = []
    for index in range(8):
        saved = _ingest(
            client,
            event_type="auth.login.failed",
            severity="high",
            source_ip="203.0.113.77",
            message="failed password for root",
        )
        burst_ids.append(saved["event_id"])
        stamps[saved["event_id"]] = burst_start + timedelta(minutes=index)

    _set_times(db_session, stamps)
    target_id = burst_ids[-1]
    before = db_session.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == target_id)
    ).scalar_one()

    response = client.get(f"/api/v1/events/{target_id}/anomaly")
    assert response.status_code == 200
    body = response.json()
    assert body["evaluated"] is True
    assert body["status"] in {"normal", "anomalous"}
    assert isinstance(body["model_score"], float)
    assert body["model_version"] == MODEL_VERSION
    assert body["training_events"] == 47
    names = [item["name"] for item in body["feature_evidence"]]
    assert "prior_events_15m" in names
    assert "same_source_failed_logins_15m" in names
    assert "event_is_failed_login" in names
    failed = next(item for item in body["feature_evidence"] if item["name"] == "event_is_failed_login")
    same_ip_failures = next(
        item for item in body["feature_evidence"] if item["name"] == "same_source_failed_logins_15m"
    )
    assert failed["value"] == 1.0
    assert same_ip_failures["value"] == 7.0

    quiet = client.get(f"/api/v1/events/{baseline_ids[30]}/anomaly")
    assert quiet.status_code == 200
    assert quiet.json()["model_score"] > body["model_score"]
    assert body["status"] == "anomalous"

    after = db_session.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == target_id)
    ).scalar_one()
    assert after.severity == before.severity
    assert after.threat_score == before.threat_score
    assert after.threat_score != body["model_score"]
