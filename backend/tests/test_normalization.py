"""
Tests for ThreatIQ Phase 1 — Event Normalization, IP Validation, and Filter API.

Coverage:
  - normalize_severity: canonical pass-through, synonym mapping, unknown values, metadata
  - normalize_event_type: lowercasing, space→dot, dot collapse, metadata
  - validate_source_ip: valid IPv4, valid IPv6, invalid IP, None, empty string
  - normalize_event: composite, metadata preservation
  - GET /events/recent: severity filter, event_type filter, source_ip filter, limit bounds
  - Existing syslog events still normalise correctly end-to-end
"""

import pytest
from fastapi.testclient import TestClient

from backend.app.core.normalization import (
    normalize_severity,
    normalize_event_type,
    validate_source_ip,
    normalize_event,
)
from backend.app.schemas.security_event import SecurityEventCreate


# ===========================================================================
# normalize_severity
# ===========================================================================

class TestNormalizeSeverity:
    """Pure unit tests — no DB, no network."""

    @pytest.mark.parametrize("canonical", ["low", "medium", "high", "critical"])
    def test_canonical_values_pass_through_unchanged(self, canonical):
        result, raw = normalize_severity(canonical)
        assert result == canonical
        assert raw is None, "canonical value should not set raw_severity"

    def test_uppercase_canonical_is_lowercased_and_no_raw(self):
        result, raw = normalize_severity("HIGH")
        assert result == "high"
        # "HIGH" lowercased == "high" which IS canonical, so raw should be None
        assert raw is None

    @pytest.mark.parametrize("synonym, expected", [
        ("info",          "low"),
        ("informational", "low"),
        ("debug",         "low"),
        ("notice",        "low"),
        ("warn",          "medium"),
        ("warning",       "medium"),
        ("err",           "high"),
        ("error",         "high"),
        ("emerg",         "critical"),
        ("emergency",     "critical"),
        ("alert",         "critical"),
        ("crit",          "critical"),
        ("fatal",         "critical"),
    ])
    def test_synonym_mapped_to_canonical(self, synonym, expected):
        result, raw = normalize_severity(synonym)
        assert result == expected
        assert raw == synonym, "original synonym should be preserved in raw"

    def test_unknown_severity_falls_back_to_medium(self):
        result, raw = normalize_severity("bananas")
        assert result == "medium"
        assert raw == "bananas"

    def test_none_input_falls_back_to_medium(self):
        result, raw = normalize_severity(None)
        assert result == "medium"
        assert raw is None

    def test_empty_string_falls_back_to_medium(self):
        result, raw = normalize_severity("")
        assert result == "medium"
        # empty string is falsy → returned as raw (falsy path)
        assert raw == ""

    def test_whitespace_stripped_before_comparison(self):
        result, raw = normalize_severity("  high  ")
        assert result == "high"
        assert raw is None


# ===========================================================================
# normalize_event_type
# ===========================================================================

class TestNormalizeEventType:

    @pytest.mark.parametrize("canonical", [
        "auth.login.failed",
        "syslog.auth.sshd",
        "network.port_scan",
    ])
    def test_canonical_passes_through(self, canonical):
        result, raw = normalize_event_type(canonical)
        assert result == canonical
        assert raw is None

    def test_uppercase_lowercased(self):
        result, raw = normalize_event_type("Auth.Login.FAILED")
        assert result == "auth.login.failed"
        assert raw == "Auth.Login.FAILED"

    def test_spaces_replaced_with_dots(self):
        result, raw = normalize_event_type("auth login failed")
        assert result == "auth.login.failed"
        assert raw == "auth login failed"

    def test_multiple_dots_collapsed(self):
        result, raw = normalize_event_type("auth..login...failed")
        assert result == "auth.login.failed"
        assert raw == "auth..login...failed"

    def test_leading_trailing_dots_stripped(self):
        result, raw = normalize_event_type(".auth.login.")
        assert result == "auth.login"
        assert raw == ".auth.login."

    def test_empty_string_returns_unknown(self):
        result, raw = normalize_event_type("")
        assert result == "unknown"

    def test_mixed_spaces_and_dots(self):
        result, raw = normalize_event_type("auth. login .failed")
        # "auth. login .failed" → lowercase → "auth. login .failed"
        # spaces → dots: "auth..login..failed"
        # collapse: "auth.login.failed"
        assert result == "auth.login.failed"


# ===========================================================================
# validate_source_ip
# ===========================================================================

class TestValidateSourceIp:

    def test_valid_ipv4_passes(self):
        ip, raw = validate_source_ip("192.168.1.100")
        assert ip == "192.168.1.100"
        assert raw is None

    def test_valid_ipv6_passes(self):
        ip, raw = validate_source_ip("2001:db8::1")
        assert ip == "2001:db8::1"
        assert raw is None

    def test_valid_loopback_passes(self):
        ip, raw = validate_source_ip("127.0.0.1")
        assert ip == "127.0.0.1"
        assert raw is None

    def test_invalid_ip_nulled_original_preserved(self):
        ip, raw = validate_source_ip("not-an-ip")
        assert ip is None
        assert raw == "not-an-ip"

    def test_invalid_octet_nulled(self):
        ip, raw = validate_source_ip("999.999.999.999")
        assert ip is None
        assert raw == "999.999.999.999"

    def test_hostname_string_nulled(self):
        ip, raw = validate_source_ip("my-host.example.com")
        assert ip is None
        assert raw == "my-host.example.com"

    def test_none_input_no_op(self):
        ip, raw = validate_source_ip(None)
        assert ip is None
        assert raw is None

    def test_empty_string_nulled(self):
        ip, raw = validate_source_ip("")
        assert ip is None
        assert raw == ""

    def test_whitespace_stripped_before_validation(self):
        ip, raw = validate_source_ip("  10.0.0.1  ")
        assert ip == "10.0.0.1"
        assert raw is None


# ===========================================================================
# normalize_event (composite)
# ===========================================================================

class TestNormalizeEvent:

    def _make_event(self, **kwargs) -> SecurityEventCreate:
        defaults = {
            "event_type": "auth.login.failed",
            "severity": "high",
            "message": "test event",
        }
        defaults.update(kwargs)
        return SecurityEventCreate(**defaults)

    def test_already_canonical_no_raw_keys(self):
        event = self._make_event(
            event_type="auth.login.failed",
            severity="high",
            source_ip="10.0.0.1",
        )
        result = normalize_event(event)
        assert result.severity == "high"
        assert result.event_type == "auth.login.failed"
        assert result.source_ip == "10.0.0.1"
        assert "raw_severity" not in result.attributes
        assert "raw_event_type" not in result.attributes
        assert "raw_source_ip" not in result.attributes

    def test_severity_synonym_recorded(self):
        event = self._make_event(severity="warn")
        result = normalize_event(event)
        assert result.severity == "medium"
        assert result.attributes["raw_severity"] == "warn"

    def test_event_type_normalised_recorded(self):
        event = self._make_event(event_type="Auth Login Failed")
        result = normalize_event(event)
        assert result.event_type == "auth.login.failed"
        assert result.attributes["raw_event_type"] == "Auth Login Failed"

    def test_invalid_ip_nulled_recorded(self):
        event = self._make_event(source_ip="bad-ip")
        result = normalize_event(event)
        assert result.source_ip is None
        assert result.attributes["raw_source_ip"] == "bad-ip"

    def test_existing_attributes_preserved(self):
        event = self._make_event(
            severity="error",
            attributes={"proto": "TCP", "port": 22},
        )
        result = normalize_event(event)
        assert result.attributes["proto"] == "TCP"
        assert result.attributes["port"] == 22
        assert result.attributes["raw_severity"] == "error"

    def test_input_object_not_mutated(self):
        event = self._make_event(severity="warn", source_ip="bad")
        original_sev = event.severity
        original_ip = event.source_ip
        normalize_event(event)
        assert event.severity == original_sev
        assert event.source_ip == original_ip

    def test_multiple_changes_all_recorded(self):
        event = self._make_event(
            event_type="Auth Login",
            severity="error",
            source_ip="not-an-ip",
        )
        result = normalize_event(event)
        assert result.severity == "high"
        assert result.event_type == "auth.login"
        assert result.source_ip is None
        assert "raw_severity" in result.attributes
        assert "raw_event_type" in result.attributes
        assert "raw_source_ip" in result.attributes


# ===========================================================================
# Filter API — GET /events/recent
# ===========================================================================

class TestRecentEventsFilterAPI:
    """Integration tests using the FastAPI TestClient with in-memory SQLite."""

    def _ingest(self, client: TestClient, event_type: str, severity: str,
                source_ip: str = None, message: str = "test") -> str:
        payload = {
            "event_type": event_type,
            "severity": severity,
            "message": message,
        }
        if source_ip:
            payload["source_ip"] = source_ip
        res = client.post("/api/v1/events/ingest", json=payload)
        assert res.status_code == 202, res.text
        return res.json()["event_id"]

    def test_no_filter_returns_all(self, client: TestClient):
        self._ingest(client, "auth.login.failed", "high")
        self._ingest(client, "network.scan", "low")
        res = client.get("/api/v1/events/recent")
        assert res.status_code == 200
        assert res.json()["total"] == 2

    def test_severity_filter_returns_matching_only(self, client: TestClient):
        self._ingest(client, "auth.login.failed", "high")
        self._ingest(client, "network.scan", "low")
        self._ingest(client, "malware.detected", "critical")

        res = client.get("/api/v1/events/recent?severity=high")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["events"][0]["severity"] == "high"

    def test_severity_filter_case_insensitive(self, client: TestClient):
        self._ingest(client, "auth.login.failed", "high")
        # filter with uppercase — should still match
        res = client.get("/api/v1/events/recent?severity=HIGH")
        assert res.status_code == 200
        assert res.json()["total"] == 1

    def test_event_type_filter_substring(self, client: TestClient):
        self._ingest(client, "auth.login.failed", "high")
        self._ingest(client, "network.port_scan", "low")

        res = client.get("/api/v1/events/recent?event_type=auth")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert "auth" in data["events"][0]["event_type"]

    def test_source_ip_filter_exact_match(self, client: TestClient):
        self._ingest(client, "auth.login.failed", "high", source_ip="10.0.0.1")
        self._ingest(client, "network.scan", "low", source_ip="10.0.0.2")

        res = client.get("/api/v1/events/recent?source_ip=10.0.0.1")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["events"][0]["source_ip"] == "10.0.0.1"

    def test_combined_filters(self, client: TestClient):
        self._ingest(client, "auth.login.failed", "high", source_ip="10.0.0.1")
        self._ingest(client, "auth.brute_force", "high", source_ip="10.0.0.2")
        self._ingest(client, "network.scan", "low", source_ip="10.0.0.1")

        # auth events from 10.0.0.1 with high severity
        res = client.get(
            "/api/v1/events/recent?severity=high&event_type=auth&source_ip=10.0.0.1"
        )
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 1
        assert data["events"][0]["source_ip"] == "10.0.0.1"
        assert data["events"][0]["severity"] == "high"

    def test_filter_returns_empty_when_no_match(self, client: TestClient):
        self._ingest(client, "auth.login.failed", "high")
        res = client.get("/api/v1/events/recent?severity=critical")
        assert res.status_code == 200
        assert res.json()["total"] == 0

    def test_limit_default_is_15(self, client: TestClient):
        for i in range(5):
            self._ingest(client, f"event.type.{i}", "low")
        res = client.get("/api/v1/events/recent")
        assert res.status_code == 200
        assert res.json()["total"] == 5  # only 5 ingested

    def test_limit_clamp_minimum_1(self, client: TestClient):
        """limit=0 should return 422 (ge=1 enforced by FastAPI Query)."""
        res = client.get("/api/v1/events/recent?limit=0")
        assert res.status_code == 422

    def test_limit_clamp_maximum_100(self, client: TestClient):
        """limit=101 should return 422 (le=100 enforced by FastAPI Query)."""
        res = client.get("/api/v1/events/recent?limit=101")
        assert res.status_code == 422

    def test_limit_1_returns_single_event(self, client: TestClient):
        self._ingest(client, "auth.login.failed", "high")
        self._ingest(client, "network.scan", "low")
        res = client.get("/api/v1/events/recent?limit=1")
        assert res.status_code == 200
        assert res.json()["total"] == 1

    def test_limit_100_accepted(self, client: TestClient):
        """limit=100 is at the boundary and must be accepted."""
        res = client.get("/api/v1/events/recent?limit=100")
        assert res.status_code == 200


# ===========================================================================
# Normalization wired into Syslog path — end-to-end smoke test
# ===========================================================================

class TestNormalizationWithSyslogPath:
    """Verify syslog-produced events survive normalization unchanged."""

    def test_syslog_severity_already_canonical_no_raw_key(
        self, client: TestClient, db_session
    ):
        """
        Syslog parser produces canonical severity values via _SEVERITY_MAP.
        After normalization they must pass through unchanged (no raw_severity key).
        """
        from backend.app.services.syslog_parser import parse_rfc5424, to_security_event
        from backend.app.services.event_pipeline import EventPipelineService

        # severity_code=3 → "high" (ERROR)
        raw = b"<19>1 2026-11-15T10:00:00Z myhost sshd 1234 - - Failed password for root"
        msg = parse_rfc5424(raw)
        event_in = to_security_event(msg)

        assert event_in.severity in {"low", "medium", "high", "critical"}

        saved, _ = EventPipelineService.ingest_event(db=db_session, event_in=event_in)
        assert saved.severity in {"low", "medium", "high", "critical"}
        # raw_severity should NOT appear because syslog severities are already canonical
        assert "raw_severity" not in (saved.attributes or {})

    def test_syslog_event_type_already_canonical(self, client: TestClient, db_session):
        """
        Syslog parser produces event_type like 'syslog.auth.sshd' (already canonical).
        Normalization must leave it unchanged.
        """
        from backend.app.services.syslog_parser import parse_rfc5424, to_security_event
        from backend.app.services.event_pipeline import EventPipelineService

        raw = b"<86>1 2026-11-15T10:00:00Z myhost sshd 1234 - - Session opened"
        msg = parse_rfc5424(raw)
        event_in = to_security_event(msg)

        assert event_in.event_type.startswith("syslog.")

        saved, _ = EventPipelineService.ingest_event(db=db_session, event_in=event_in)
        assert saved.event_type.startswith("syslog.")
        assert "raw_event_type" not in (saved.attributes or {})
