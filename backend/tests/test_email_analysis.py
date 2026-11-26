"""Email analysis uses the real classifier and records through the event pipeline once."""

from sqlalchemy import func, select

from backend.app.models.security_event import SecurityEvent
from backend.app.services.phishguard.classifier import EVENT_TYPE, PhishguardUnavailable

PHISHING = (
    "URGENT: Your account has been suspended. "
    "Click here to verify your password at http://secure-login.example/update"
)


def test_analyze_returns_real_probability_and_model_version(client):
    response = client.post("/api/v1/email/analyze", json={"body": PHISHING})
    assert response.status_code == 200
    body = response.json()
    assert body["prediction"] in {"phishing", "legitimate"}
    assert body["predicted_class"] in {0, 1}
    assert 0.0 <= body["phishing_probability"] <= 1.0
    assert body["prediction"] == "phishing"
    assert body["phishing_probability"] > 0.5
    assert body["model_version"] == "phishguard-linearsvc-calibrated@2026-10-10"
    assert body["sklearn_version"] == "1.7.2"
    assert body["recorded"] is False
    assert body["event_id"] is None
    assert "confidence" not in body
    assert body["token_contributions"]
    assert all(item["method"] == "tfidf_linear_weight" for item in body["token_contributions"])
    assert "not SHAP" in body["attribution_note"]


def test_blank_body_is_rejected(client):
    response = client.post("/api/v1/email/analyze", json={"body": "   "})
    assert response.status_code == 422


def test_record_uses_pipeline_once(client, db_session):
    payload = {"subject": "Account notice", "sender": "alerts@example.test", "body": PHISHING, "record": True}
    first = client.post("/api/v1/email/analyze", json=payload)
    second = client.post("/api/v1/email/analyze", json=payload)
    assert first.status_code == 200
    assert second.status_code == 200
    first_body = first.json()
    second_body = second.json()
    assert first_body["recorded"] is True
    assert first_body["duplicate"] is False
    assert second_body["recorded"] is False
    assert second_body["duplicate"] is True
    assert second_body["event_id"] == first_body["event_id"]

    count = db_session.execute(
        select(func.count()).select_from(SecurityEvent).where(SecurityEvent.event_type == EVENT_TYPE)
    ).scalar_one()
    assert count == 1
    stored = db_session.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == first_body["event_id"])
    ).scalar_one()
    assert stored.attributes["phishing_probability"] == first_body["phishing_probability"]
    assert stored.threat_score == round(first_body["phishing_probability"] * 100.0, 2)
    assert stored.attributes["model_version"] == first_body["model_version"]


def test_suspicious_urls_are_defanged_and_not_fetched(client):
    body = "Review http://192.168.1.50/login.php and http://phish.xyz/pay now."
    response = client.post("/api/v1/email/analyze", json={"body": body, "record": False})
    assert response.status_code == 200
    urls = response.json()["suspicious_urls"]
    assert urls
    assert all("http://" not in item["defanged"] and "https://" not in item["defanged"] for item in urls)
    assert any("IP-address" in item["reason"] for item in urls)
    assert any("top-level domain" in item["reason"] for item in urls)


def test_unavailable_model_returns_503(client, monkeypatch):
    def fail(*_args, **_kwargs):
        raise PhishguardUnavailable("PHISHGUARD artifact is unavailable. No prediction was produced.")

    monkeypatch.setattr("backend.app.api.v1.endpoints.email.analyze_email", fail)
    response = client.post("/api/v1/email/analyze", json={"body": PHISHING})
    assert response.status_code == 503
    assert "No prediction" in response.json()["detail"]
