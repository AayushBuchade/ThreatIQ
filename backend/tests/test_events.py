"""
Test Suite for Security Event Ingestion and Database Roundtrip
"""

from fastapi.testclient import TestClient


def test_fullstack_event_ping_integration(client: TestClient):
    """
    Verifies the end-to-end integration:
    HTTP POST payload -> Pydantic validation -> Database write -> DB read -> Roundtrip response.
    """
    payload = {
        "event_type": "network.port_scan",
        "severity": "high",
        "source_ip": "10.0.4.12",
        "destination_ip": "192.168.1.1",
        "message": "Syn scan detected on ports 22, 80, 443",
        "attributes": {
            "ports_scanned": [22, 80, 443],
            "protocol": "TCP"
        }
    }

    response = client.post("/api/v1/events/test-ping", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["success"] is True
    assert data["event_id"].startswith("tiq-")
    assert data["db_roundtrip_ms"] >= 0.0

    persisted = data["persisted_event"]
    assert persisted["event_type"] == "network.port_scan"
    assert persisted["severity"] == "high"
    assert persisted["source_ip"] == "10.0.4.12"
    assert persisted["attributes"]["protocol"] == "TCP"
    assert persisted["threat_score"] == 85.0


def test_event_ingest_and_recent_query(client: TestClient):
    """Verifies that ingested events appear in the recent events query."""
    payload = {
        "event_type": "auth.brute_force",
        "severity": "critical",
        "source_ip": "203.0.113.5",
        "message": "Multiple failed SSH root logins from external IP"
    }

    ingest_res = client.post("/api/v1/events/ingest", json=payload)
    assert ingest_res.status_code == 202
    ingested_id = ingest_res.json()["event_id"]

    # Query recent events
    recent_res = client.get("/api/v1/events/recent?limit=10")
    assert recent_res.status_code == 200
    recent_data = recent_res.json()
    assert recent_data["total"] >= 1

    event_ids = [e["event_id"] for e in recent_data["events"]]
    assert ingested_id in event_ids


def test_event_validation_error(client: TestClient):
    """Verifies that invalid payloads are rejected with 422 Unprocessable Entity."""
    # Missing required message and event_type
    invalid_payload = {
        "source_ip": "10.0.0.1"
    }

    response = client.post("/api/v1/events/test-ping", json=invalid_payload)
    assert response.status_code == 422


def _ingest(client: TestClient, **overrides) -> dict:
    payload = {
        "event_type": "auth.login.failed",
        "severity": "high",
        "source_ip": "203.0.113.8",
        "message": "failed password for root",
    }
    payload.update(overrides)
    response = client.post("/api/v1/events/ingest", json=payload)
    assert response.status_code == 202, response.text
    return response.json()


def test_summary_counts_are_not_limited_to_the_recent_page(client: TestClient):
    _ingest(client, severity="critical", message="first critical")
    _ingest(client, severity="high", message="second high")
    _ingest(client, severity="low", event_type="network.scan", message="third low")

    recent = client.get("/api/v1/events/recent?limit=1")
    assert recent.status_code == 200
    assert recent.json()["total"] == 1

    summary = client.get("/api/v1/events/summary")
    assert summary.status_code == 200
    body = summary.json()
    assert body["total"] == 3
    assert body["by_severity"]["critical"] == 1
    assert body["by_severity"]["high"] == 1
    assert body["by_severity"]["low"] == 1
    assert body["by_severity"]["medium"] == 0


def test_summary_and_recent_search_share_filters(client: TestClient):
    _ingest(client, message="ssh login failure from edge router", source_ip="198.51.100.9")
    _ingest(client, event_type="network.port_scan", severity="medium", message="unrelated scan")

    summary = client.get("/api/v1/events/summary?q=edge%20router&severity=high")
    assert summary.status_code == 200
    assert summary.json()["total"] == 1
    assert summary.json()["by_severity"]["high"] == 1

    recent = client.get("/api/v1/events/recent?q=198.51.100.9")
    assert recent.status_code == 200
    assert recent.json()["total"] == 1
    assert recent.json()["events"][0]["source_ip"] == "198.51.100.9"
    assert recent.json()["events"][0]["updated_at"]
