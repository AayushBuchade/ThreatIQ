"""
Test Suite for Healthcheck API Endpoint
"""

from fastapi.testclient import TestClient


def test_healthcheck_endpoint(client: TestClient):
    """Verifies that /api/v1/health returns 200 and valid schema."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] in ["ok", "degraded"]
    assert "version" in data
    assert "database" in data
    assert "response_time_ms" in data
    assert data["response_time_ms"] >= 0.0
    assert "timestamp" in data


def test_root_endpoint(client: TestClient):
    """Verifies root metadata endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["platform"] == "ThreatIQ"
    assert "Phase 0" in data["phase"]
