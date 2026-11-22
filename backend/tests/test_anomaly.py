"""Isolation Forest assessments stay off the stored severity and threat score."""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.app.models.security_event import SecurityEvent
from backend.app.services.anomaly_detector import (
    MIN_TRAINING_EVENTS,
    MODEL_VERSION,
    metrics_from_labels,
)


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
    assert "confidence" not in body
    assert "not a confidence percentage" in body["score_direction"].lower()
    assert "more normal" in body["score_direction"].lower()
    assert "more anomalous" in body["score_direction"].lower()
    deviations = body["top_deviations"]
    assert deviations
    assert deviations == sorted(deviations, key=lambda item: abs(item["z_score"]), reverse=True)
    assert all(item["comparison"] == "statistical_z_score" for item in deviations)
    assert all(item["explanation"] == "not_shap" for item in deviations)

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


def test_metrics_are_not_calculated_without_labels():
    result = metrics_from_labels([], [])
    assert result["status"] == "not_evaluated"
    assert result["evaluated"] is False
    assert result["precision"] is None
    assert result["recall"] is None
    assert result["f1"] is None
    assert result["confusion_matrix"] is None


def test_metrics_use_only_supplied_labels():
    result = metrics_from_labels(
        ["anomalous", "normal", "anomalous", "normal"],
        ["anomalous", "normal", "normal", "normal"],
    )
    assert result["status"] == "evaluated"
    assert result["precision"] == 1.0
    assert result["recall"] == 0.5
    assert result["f1"] == 0.666667
    assert result["confusion_matrix"]["labels"] == ["normal", "anomalous"]
    assert result["confusion_matrix"]["matrix"] == [[2, 0], [1, 1]]


def test_severity_is_not_an_evaluation_label(client: TestClient):
    _ingest(client, severity="critical", message="critical without an evaluation label")
    response = client.get("/api/v1/events/anomaly-evaluation")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "not_evaluated"
    assert body["evaluated"] is False
    assert body["precision"] is None
    assert body["labeled_events"] == 0
    assert body["confusion_matrix"] is None


def test_labeled_evaluation_excludes_labeled_rows_from_training(client: TestClient, db_session):
    start = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
    stamps = {}
    early = _ingest(
        client,
        message="labeled too early",
        attributes={"evaluation_label": "normal"},
    )
    stamps[early["event_id"]] = start

    for index in range(MIN_TRAINING_EVENTS + 1):
        saved = _ingest(client, message=f"unlabeled heartbeat {index}")
        stamps[saved["event_id"]] = start + timedelta(hours=index + 1)

    late = _ingest(
        client,
        event_type="auth.login.failed",
        severity="low",
        source_ip="203.0.113.88",
        message="failed password for root",
        attributes={"evaluation_label": "anomalous"},
    )
    stamps[late["event_id"]] = start + timedelta(days=4)
    _set_times(db_session, stamps)

    response = client.get("/api/v1/events/anomaly-evaluation")
    assert response.status_code == 200
    body = response.json()
    assert body["labeled_events"] == 2
    assert body["unscored_events"] == 1
    assert early["event_id"] in body["excluded_from_training"]
    assert late["event_id"] in body["excluded_from_training"]
    assert body["status"] == "evaluated"
    scored_ids = [item["event_id"] for item in body["scored"]]
    assert scored_ids == [late["event_id"]]
    assert early["event_id"] not in scored_ids
    assert body["scored"][0]["training_events"] == MIN_TRAINING_EVENTS + 1
    assert body["confusion_matrix"]["matrix"]
    assert sum(sum(row) for row in body["confusion_matrix"]["matrix"]) == 1
    assert body["precision"] is not None
    assert body["recall"] is not None
    assert body["f1"] is not None
