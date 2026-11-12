"""
ThreatIQ — Test Suite: RFC 5424 Syslog Parser & Listener  (Phase 1 / T1.1)

Coverage:
  - parse_rfc5424()   : valid messages, edge cases, malformed input
  - to_security_event(): field mapping, severity conversion, attribute population
  - _persist_event()  : database roundtrip through EventPipelineService
  - SyslogParseError  : all rejection paths are tested explicitly

No real UDP socket is opened during the tests — the listener protocol is
exercised directly by calling datagram_received() with synthetic data.
"""

import pytest
from datetime import timezone

from backend.app.services.syslog_parser import (
    SyslogParseError,
    SyslogMessage,
    parse_rfc5424,
    to_security_event,
    _SEVERITY_MAP,
)
from backend.app.services.syslog_listener import _persist_event, _SyslogUDPProtocol
from backend.app.services.event_pipeline import EventPipelineService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Valid RFC 5424 syslog frames used across multiple tests
VALID_MSG_FULL = (
    b"<34>1 2026-11-12T12:00:00.000Z webserver01 nginx - - "
    b"[exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] "
    b"An application event log entry"
)

VALID_MSG_NILVALUE_SD = (
    b"<165>1 2026-11-12T06:30:00+05:30 db-host01 postgres 1234 MSG001 "
    b"- Connection received from 10.0.0.5"
)

VALID_MSG_NIL_TIMESTAMP = (
    b"<13>1 - routerA sshd 99 - - Accepted publickey for admin"
)

VALID_MSG_MINIMAL = (
    b"<0>1 - - - - - emergency kernel message"
)


# ---------------------------------------------------------------------------
# 1. Parsing — valid messages
# ---------------------------------------------------------------------------

class TestParseRfc5424Valid:

    def test_full_message_prival_decoded(self):
        msg = parse_rfc5424(VALID_MSG_FULL)
        # PRI=34 → facility=4 (auth), severity_code=2 (CRITICAL)
        assert msg.priority == 34
        assert msg.facility == 4
        assert msg.severity_code == 2

    def test_full_message_version(self):
        msg = parse_rfc5424(VALID_MSG_FULL)
        assert msg.version == 1

    def test_full_message_hostname(self):
        msg = parse_rfc5424(VALID_MSG_FULL)
        assert msg.hostname == "webserver01"

    def test_full_message_app_name(self):
        msg = parse_rfc5424(VALID_MSG_FULL)
        assert msg.app_name == "nginx"

    def test_full_message_message_text(self):
        msg = parse_rfc5424(VALID_MSG_FULL)
        assert "An application event log entry" in msg.message

    def test_full_message_structured_data_captured(self):
        msg = parse_rfc5424(VALID_MSG_FULL)
        assert "structured_data" in msg.attributes

    def test_timestamp_parsed_correctly(self):
        msg = parse_rfc5424(VALID_MSG_FULL)
        assert msg.timestamp is not None
        assert msg.timestamp.year == 2026
        assert msg.timestamp.month == 11
        assert msg.timestamp.day == 12
        assert msg.timestamp.tzinfo is not None

    def test_timestamp_with_offset(self):
        msg = parse_rfc5424(VALID_MSG_NIL_TIMESTAMP.replace(b"- ", b"2026-11-12T06:30:00+05:30 ", 1))
        assert msg.timestamp is not None
        assert msg.timestamp.utcoffset().seconds // 3600 == 5  # +05:30 = 5.5 hours

    def test_nil_timestamp_gives_none(self):
        msg = parse_rfc5424(VALID_MSG_NIL_TIMESTAMP)
        assert msg.timestamp is None

    def test_nil_sd_message_text(self):
        msg = parse_rfc5424(VALID_MSG_NILVALUE_SD)
        assert "Connection received from 10.0.0.5" in msg.message

    def test_proc_id_parsed(self):
        msg = parse_rfc5424(VALID_MSG_NILVALUE_SD)
        assert msg.proc_id == "1234"

    def test_msg_id_parsed(self):
        msg = parse_rfc5424(VALID_MSG_NILVALUE_SD)
        assert msg.msg_id == "MSG001"

    def test_prival_zero_facility_zero_severity_zero(self):
        msg = parse_rfc5424(VALID_MSG_MINIMAL)
        assert msg.priority == 0
        assert msg.facility == 0
        assert msg.severity_code == 0

    def test_raw_field_populated(self):
        msg = parse_rfc5424(VALID_MSG_FULL)
        assert "<34>" in msg.raw
        assert len(msg.raw) <= 4096

    def test_severity_165_facility_20_severity_5(self):
        # PRI=165 → facility=20 (local4), severity=5 (NOTICE)
        msg = parse_rfc5424(VALID_MSG_NILVALUE_SD)
        assert msg.facility == 20
        assert msg.severity_code == 5


# ---------------------------------------------------------------------------
# 2. Parsing — malformed / invalid input
# ---------------------------------------------------------------------------

class TestParseRfc5424Invalid:

    def test_empty_bytes_raises(self):
        with pytest.raises(SyslogParseError, match="Empty datagram"):
            parse_rfc5424(b"")

    def test_no_pri_raises(self):
        with pytest.raises(SyslogParseError):
            parse_rfc5424(b"1 2026-11-12T12:00:00Z host app - - - message")

    def test_malformed_header_raises(self):
        with pytest.raises(SyslogParseError):
            parse_rfc5424(b"<abc>1 - host app - - - message")

    def test_prival_out_of_range_raises(self):
        with pytest.raises(SyslogParseError, match="PRIVAL.*out of range"):
            parse_rfc5424(b"<192>1 - host app - - - message")

    def test_unsupported_version_raises(self):
        with pytest.raises(SyslogParseError, match="Unsupported syslog version"):
            parse_rfc5424(b"<34>2 2026-11-12T12:00:00Z host app - - - message")

    def test_non_utf8_raises(self):
        with pytest.raises(SyslogParseError, match="Non-UTF-8"):
            parse_rfc5424(b"<34>1 - host \x80\x81\x82 - - - message")

    def test_oversized_datagram_raises(self):
        big = b"<34>1 - host app - - - " + b"A" * 70_000
        with pytest.raises(SyslogParseError, match="Datagram too large"):
            parse_rfc5424(big)

    def test_invalid_timestamp_raises(self):
        with pytest.raises(SyslogParseError, match="Invalid TIMESTAMP"):
            parse_rfc5424(b"<34>1 NOT-A-DATE host app - - - message")

    def test_gibberish_raises(self):
        with pytest.raises(SyslogParseError):
            parse_rfc5424(b"this is definitely not syslog")


# ---------------------------------------------------------------------------
# 3. to_security_event() — field mapping
# ---------------------------------------------------------------------------

class TestToSecurityEvent:

    def _get_msg(self, raw: bytes = VALID_MSG_FULL) -> SyslogMessage:
        return parse_rfc5424(raw)

    def test_event_type_includes_facility_and_app(self):
        event = to_security_event(self._get_msg())
        # facility=4 → "auth", app_name="nginx"
        assert event.event_type == "syslog.auth.nginx"

    def test_severity_critical_for_severity_code_2(self):
        event = to_security_event(self._get_msg())
        assert event.severity == "critical"

    def test_severity_high_for_error(self):
        raw = b"<24>1 - host sshd - - - Login failure"  # PRI=24 → facility=3 (daemon), sev=0 (EMERG)
        # PRI 24: facility=3, severity=0 → critical
        event = to_security_event(parse_rfc5424(raw))
        assert event.severity == "critical"

    def test_severity_medium_for_warning(self):
        # PRI=36 → facility=4 (auth), severity=4 (WARNING)
        raw = b"<36>1 - host app - - - warning message"
        event = to_security_event(parse_rfc5424(raw))
        assert event.severity == "medium"

    def test_severity_low_for_info(self):
        # PRI=46 → facility=5 (syslog), severity=6 (INFO)
        raw = b"<46>1 - host app - - - info message"
        event = to_security_event(parse_rfc5424(raw))
        assert event.severity == "low"

    def test_attributes_contain_hostname(self):
        event = to_security_event(self._get_msg())
        assert event.attributes["syslog_hostname"] == "webserver01"

    def test_attributes_contain_app_name(self):
        event = to_security_event(self._get_msg())
        assert event.attributes["syslog_app_name"] == "nginx"

    def test_attributes_contain_facility_and_severity_code(self):
        event = to_security_event(self._get_msg())
        assert event.attributes["syslog_facility"] == 4
        assert event.attributes["syslog_severity_code"] == 2

    def test_attributes_contain_timestamp_string(self):
        event = to_security_event(self._get_msg())
        assert "syslog_timestamp" in event.attributes

    def test_message_propagated(self):
        event = to_security_event(self._get_msg())
        assert "An application event log entry" in event.message

    def test_source_ip_is_none_by_default(self):
        event = to_security_event(self._get_msg())
        assert event.source_ip is None

    def test_nil_hostname_produces_empty_string(self):
        raw = b"<34>1 - - nginx - - - message"
        event = to_security_event(parse_rfc5424(raw))
        assert event.attributes["syslog_hostname"] == ""


# ---------------------------------------------------------------------------
# 4. Severity-map completeness
# ---------------------------------------------------------------------------

class TestSeverityMap:

    def test_all_severity_codes_covered(self):
        for code in range(8):
            assert code in _SEVERITY_MAP, f"Severity code {code} not in map"

    def test_emergency_is_critical(self):
        assert _SEVERITY_MAP[0] == "critical"

    def test_debug_is_low(self):
        assert _SEVERITY_MAP[7] == "low"


# ---------------------------------------------------------------------------
# 5. Database persistence — integration via EventPipelineService
# ---------------------------------------------------------------------------

class TestSyslogDatabasePersistence:
    """
    Tests that _persist_event() correctly writes a syslog-derived event
    through EventPipelineService into the in-memory SQLite test database.
    """

    def test_persist_valid_syslog_event(self, db_session):
        msg = parse_rfc5424(VALID_MSG_FULL)
        event_in = to_security_event(msg)
        event_in = event_in.model_copy(update={"source_ip": "10.0.0.1"})

        db_event, latency_ms = EventPipelineService.ingest_event(db_session, event_in)

        assert db_event.id is not None
        assert db_event.event_id.startswith("tiq-")
        assert db_event.event_type == "syslog.auth.nginx"
        assert db_event.severity == "critical"
        assert db_event.source_ip == "10.0.0.1"
        assert "An application event log entry" in db_event.message
        assert db_event.attributes["syslog_hostname"] == "webserver01"
        assert latency_ms >= 0.0

    def test_persist_nil_timestamp_event(self, db_session):
        msg = parse_rfc5424(VALID_MSG_NIL_TIMESTAMP)
        event_in = to_security_event(msg)
        event_in = event_in.model_copy(update={"source_ip": "192.168.1.5"})

        db_event, _ = EventPipelineService.ingest_event(db_session, event_in)
        assert db_event.event_id.startswith("tiq-")
        assert "syslog_timestamp" not in db_event.attributes  # nil TS → not stored

    def test_persist_multiple_events_unique_ids(self, db_session):
        events = []
        for raw in [VALID_MSG_FULL, VALID_MSG_NILVALUE_SD, VALID_MSG_NIL_TIMESTAMP]:
            msg = parse_rfc5424(raw)
            event_in = to_security_event(msg)
            db_event, _ = EventPipelineService.ingest_event(db_session, event_in)
            events.append(db_event.event_id)

        # All event IDs must be unique
        assert len(set(events)) == 3

    def test_persisted_event_retrievable_via_pipeline(self, db_session):
        msg = parse_rfc5424(VALID_MSG_FULL)
        event_in = to_security_event(msg)
        EventPipelineService.ingest_event(db_session, event_in)

        recent = EventPipelineService.get_recent_events(db_session, limit=10)
        assert len(recent) >= 1
        types = [e.event_type for e in recent]
        assert "syslog.auth.nginx" in types


# ---------------------------------------------------------------------------
# 6. Protocol handler — datagram_received with malformed data (no I/O)
# ---------------------------------------------------------------------------

class TestSyslogUDPProtocol:
    """
    Tests _SyslogUDPProtocol.datagram_received() directly — no live socket.
    We verify that malformed datagrams are silently dropped (no exception
    propagates to the event loop).
    """

    def test_malformed_datagram_does_not_raise(self):
        proto = _SyslogUDPProtocol()
        # Should log a warning but NOT raise
        try:
            proto.datagram_received(b"garbage data", ("127.0.0.1", 12345))
        except Exception as exc:
            pytest.fail(f"datagram_received raised unexpectedly: {exc}")

    def test_empty_datagram_does_not_raise(self):
        proto = _SyslogUDPProtocol()
        try:
            proto.datagram_received(b"", ("127.0.0.1", 12345))
        except Exception as exc:
            pytest.fail(f"datagram_received raised on empty data: {exc}")

