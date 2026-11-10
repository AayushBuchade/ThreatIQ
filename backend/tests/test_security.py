"""
Test Suite for Security Headers and Non-Destructive Enforcement
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.core.security import enforce_non_destructive


def test_security_headers_present(client: TestClient):
    """Verifies that all required defense-in-depth headers are returned."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200

    headers = response.headers
    assert "x-request-id" in headers
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("x-xss-protection") == "1; mode=block"
    assert headers.get("referrer-policy") == "strict-origin-when-cross-origin"


def test_non_destructive_enforcement():
    """Verifies that destructive automated actions are rejected by policy."""
    with pytest.raises(PermissionError) as exc_info:
        enforce_non_destructive("terminate_host")

    assert "strictly disallows destructive automation" in str(exc_info.value) or "blocked" in str(exc_info.value)
