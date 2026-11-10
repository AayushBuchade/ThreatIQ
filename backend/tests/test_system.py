"""
Test Suite for System Status and Modules Endpoints
"""

from fastapi.testclient import TestClient


def test_system_status_endpoint(client: TestClient):
    """Verifies system status, uptime, and safety constraints."""
    response = client.get("/api/v1/system/status")
    assert response.status_code == 200

    data = response.json()
    assert data["platform"] == "ThreatIQ"
    assert "version" in data
    assert data["uptime_seconds"] >= 0.0
    assert data["destructive_actions_allowed"] is False
    assert data["features_total"] == 12


def test_system_modules_endpoint(client: TestClient):
    """Verifies that all 12 platform modules are listed with valid statuses."""
    response = client.get("/api/v1/system/modules")
    assert response.status_code == 200

    data = response.json()
    assert data["total_modules"] == 12
    modules = data["modules"]
    assert len(modules) == 12

    module_ids = [m["id"] for m in modules]
    assert module_ids == list(range(1, 13))

    for m in modules:
        assert m["status"] in ["Completed", "In Progress", "Upcoming", "Blocked"]
        assert len(m["name"]) > 0
        assert len(m["description"]) > 0
