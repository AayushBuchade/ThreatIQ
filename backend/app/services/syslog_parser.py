"""
ThreatIQ — RFC 5424 Syslog Parser

Parses raw UDP datagrams according to RFC 5424 and converts them into
SecurityEventCreate objects suitable for the EventPipelineService.

Design rules:
  - Pure functions only (no I/O, no DB access). Easy to unit-test in isolation.
  - Malformed messages raise SyslogParseError — the caller decides how to log / discard.
  - Only the fields required for ThreatIQ Phase-1 ingestion are extracted:
    priority, facility, severity-level, timestamp, hostname, app-name, msg.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from backend.app.schemas.security_event import SecurityEventCreate

# ---------------------------------------------------------------------------
# Public error type
# ---------------------------------------------------------------------------


class SyslogParseError(ValueError):
    """Raised when a datagram cannot be decoded as a valid RFC 5424 message."""


# ---------------------------------------------------------------------------
# Data container for a decoded syslog frame
# ---------------------------------------------------------------------------

@dataclass
class SyslogMessage:
    """Decoded, normalised fields from a single RFC 5424 syslog frame."""

    priority: int               # Raw PRI value (0-191)
    facility: int               # facility code = priority // 8
    severity_code: int          # severity code = priority % 8  (0=EMERG … 7=DEBUG)
    version: int                # Syslog version (should be 1 for RFC 5424)
    timestamp: Optional[datetime]
    hostname: str
    app_name: str
    proc_id: str
    msg_id: str
    message: str
    raw: str                    # Original datagram (truncated to 4096 chars for safety)
    attributes: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Severity-code → ThreatIQ severity label mapping
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[int, str] = {
    0: "critical",   # EMERGENCY
    1: "critical",   # ALERT
    2: "critical",   # CRITICAL
    3: "high",       # ERROR
    4: "medium",     # WARNING
    5: "medium",     # NOTICE
    6: "low",        # INFORMATIONAL
    7: "low",        # DEBUG
}

# Facility-code names (RFC 5424, section 6.2.1)
_FACILITY_NAMES: dict[int, str] = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

# ---------------------------------------------------------------------------
# RFC 5424 header pattern
#
# Format:
#   <PRIVAL>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP MSG
#
# TIMESTAMP may be NILVALUE ("-") or RFC 3339 (e.g. 2026-11-12T12:00:00.000Z)
# ---------------------------------------------------------------------------

_HEADER_RE = re.compile(
    r"^<(?P<prival>\d{1,3})>"       # PRI  <0-191>
    r"(?P<version>\d+) "            # VERSION (must be 1)
    r"(?P<timestamp>\S+) "          # TIMESTAMP or "-"
    r"(?P<hostname>\S+) "           # HOSTNAME or "-"
    r"(?P<app_name>\S+) "           # APP-NAME or "-"
    r"(?P<proc_id>\S+) "            # PROCID or "-"
    r"(?P<msg_id>\S+)"              # MSGID or "-"
    r"(?P<remainder>.*)$",          # SP STRUCTURED-DATA MSG (we keep as-is)
    re.DOTALL,
)

# Strip STRUCTURED-DATA block (we capture it in `attributes` but don't deep-parse it)
_STRUCTURED_RE = re.compile(r"^ \[(?P<sd>[^\]]*)\](?P<msg>.*)$", re.DOTALL)

# Reasonable maximum datagram size to guard against DoS
_MAX_DATAGRAM_BYTES = 65_535


# ---------------------------------------------------------------------------
# Public parsing API
# ---------------------------------------------------------------------------

def parse_rfc5424(raw_bytes: bytes) -> SyslogMessage:
    """
    Parse a raw UDP datagram as an RFC 5424 syslog message.

    Args:
        raw_bytes: The exact bytes received from the UDP socket.

    Returns:
        A populated :class:`SyslogMessage` instance.

    Raises:
        SyslogParseError: For any deviation that makes safe parsing impossible.
    """
    if not raw_bytes:
        raise SyslogParseError("Empty datagram")

    # Hard cap: guard against huge payloads
    if len(raw_bytes) > _MAX_DATAGRAM_BYTES:
        raise SyslogParseError(
            f"Datagram too large: {len(raw_bytes)} bytes (max {_MAX_DATAGRAM_BYTES})"
        )

    try:
        raw_text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SyslogParseError(f"Non-UTF-8 datagram: {exc}") from exc

    m = _HEADER_RE.match(raw_text)
    if not m:
        raise SyslogParseError(f"RFC 5424 header not recognised: {raw_text[:80]!r}")

    # --- PRIVAL / FACILITY / SEVERITY ---
    prival = int(m.group("prival"))
    if prival > 191:
        raise SyslogParseError(f"PRIVAL {prival} out of range (0-191)")
    facility = prival >> 3        # == prival // 8
    severity_code = prival & 0x7  # == prival % 8

    # --- VERSION ---
    version = int(m.group("version"))
    if version != 1:
        raise SyslogParseError(f"Unsupported syslog version: {version} (expected 1)")

    # --- TIMESTAMP ---
    ts_str = m.group("timestamp")
    timestamp: Optional[datetime] = None
    if ts_str != "-":
        timestamp = _parse_timestamp(ts_str)

    # --- HOSTNAME / APP-NAME / PROC-ID / MSG-ID ---
    hostname = _nilvalue(m.group("hostname"))
    app_name = _nilvalue(m.group("app_name"))
    proc_id = _nilvalue(m.group("proc_id"))
    msg_id = _nilvalue(m.group("msg_id"))

    # --- STRUCTURED-DATA + MSG ---
    remainder = m.group("remainder")
    attributes: dict = {}
    message = ""

    if remainder:
        # remainder starts with SP after MSGID
        body = remainder if not remainder.startswith(" ") else remainder[1:]
        if body.startswith("["):
            sd_m = _STRUCTURED_RE.match(" " + body[body.find("["):])
            if sd_m:
                attributes["structured_data"] = sd_m.group("sd")
                message = sd_m.group("msg").strip()
            else:
                message = body
        elif body.startswith("-"):
            # NILVALUE structured data
            message = body[1:].strip() if len(body) > 1 else ""
        else:
            message = body.strip()

    # Fallback: use app_name as the message if everything was nil
    if not message:
        message = f"syslog event from {hostname or 'unknown'}"

    return SyslogMessage(
        priority=prival,
        facility=facility,
        severity_code=severity_code,
        version=version,
        timestamp=timestamp,
        hostname=hostname,
        app_name=app_name,
        proc_id=proc_id,
        msg_id=msg_id,
        message=message,
        raw=raw_text[:4096],
        attributes=attributes,
    )


def to_security_event(msg: SyslogMessage) -> SecurityEventCreate:
    """
    Convert a parsed :class:`SyslogMessage` into a :class:`SecurityEventCreate`.

    Event-type is derived from facility name + "." + app_name so the pipeline
    can filter / route by category later.
    """
    facility_name = _FACILITY_NAMES.get(msg.facility, f"facility{msg.facility}")
    app_slug = msg.app_name.lower().replace(" ", "_") if msg.app_name else "unknown"
    event_type = f"syslog.{facility_name}.{app_slug}"

    severity = _SEVERITY_MAP.get(msg.severity_code, "low")

    extra_attrs: dict = {
        "syslog_hostname": msg.hostname,
        "syslog_app_name": msg.app_name,
        "syslog_proc_id": msg.proc_id,
        "syslog_msg_id": msg.msg_id,
        "syslog_facility": msg.facility,
        "syslog_severity_code": msg.severity_code,
        "syslog_version": msg.version,
        **msg.attributes,
    }
    if msg.timestamp:
        extra_attrs["syslog_timestamp"] = msg.timestamp.isoformat()

    return SecurityEventCreate(
        event_type=event_type,
        severity=severity,
        source_ip=None,          # UDP source IP is handled at listener level
        destination_ip=None,
        message=msg.message,
        attributes=extra_attrs,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nilvalue(value: str) -> str:
    """Return empty string for RFC 5424 NILVALUE ('-'), else the raw value."""
    return "" if value == "-" else value


def _parse_timestamp(ts_str: str) -> datetime:
    """
    Parse an RFC 3339 / ISO 8601 timestamp string.

    Raises SyslogParseError on failure so the caller can discard bad frames.
    """
    # Python 3.11+ datetime.fromisoformat handles 'Z' suffix natively.
    # For 3.10 compatibility we normalise 'Z' → '+00:00'.
    normalised = ts_str.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalised)
        # Ensure timezone-aware
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError as exc:
        raise SyslogParseError(f"Invalid TIMESTAMP {ts_str!r}: {exc}") from exc

