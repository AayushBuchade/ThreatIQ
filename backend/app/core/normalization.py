"""
ThreatIQ — Event Normalization Utilities

Pure, side-effect-free functions that coerce incoming event fields into the
canonical ThreatIQ format before persistence. Applies to all ingestion paths
(REST, Syslog UDP, future TCP).

Normalization rules:
  - severity  : lowercase + strip → map synonyms → canonical label (low/medium/high/critical)
  - event_type: lowercase + strip, collapse whitespace/dots
  - source_ip : validate via stdlib `ipaddress`; invalid → None
  - Original pre-normalization values are stored in `attributes` as `raw_*` keys
    only when the value was actually changed/nulled, so callers can audit.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple

from backend.app.schemas.security_event import SecurityEventCreate

# ---------------------------------------------------------------------------
# Canonical severity values and synonym map
# ---------------------------------------------------------------------------

_CANONICAL_SEVERITIES = {"low", "medium", "high", "critical"}

# Map alternate spellings → canonical label
_SEVERITY_SYNONYMS: dict[str, str] = {
    # low
    "info":          "low",
    "informational": "low",
    "debug":         "low",
    "notice":        "low",
    # medium
    "warn":          "medium",
    "warning":       "medium",
    # high
    "err":           "high",
    "error":         "high",
    # critical
    "emerg":         "critical",
    "emergency":     "critical",
    "alert":         "critical",
    "crit":          "critical",
    "fatal":         "critical",
}

_DEFAULT_SEVERITY = "medium"

# Collapse multiple consecutive dots in event_type strings
_MULTI_DOT_RE = re.compile(r"\.{2,}")


# ---------------------------------------------------------------------------
# Public normalization helpers
# ---------------------------------------------------------------------------

def normalize_severity(raw: Optional[str]) -> Tuple[str, Optional[str]]:
    """
    Coerce *raw* to a canonical severity label.

    Returns:
        (normalized_severity, original_value_if_changed_else_None)
        If *raw* is already canonical the second element is None (unchanged).
    """
    if not raw:
        return _DEFAULT_SEVERITY, raw  # treat falsy as changed → store ""

    cleaned = raw.strip().lower()

    if cleaned in _CANONICAL_SEVERITIES:
        return cleaned, None if cleaned == raw.strip().lower() else raw

    mapped = _SEVERITY_SYNONYMS.get(cleaned)
    if mapped:
        return mapped, raw

    # Unknown value → fall back to default, preserve original
    return _DEFAULT_SEVERITY, raw


def normalize_event_type(raw: str) -> Tuple[str, Optional[str]]:
    """
    Coerce *raw* to a canonical event_type string:
      - lowercase + strip
      - spaces → dots
      - collapse consecutive dots

    Returns:
        (normalized_event_type, original_if_changed_else_None)
    """
    if not raw:
        return "unknown", raw

    normalised = raw.strip().lower()
    normalised = normalised.replace(" ", ".")
    normalised = _MULTI_DOT_RE.sub(".", normalised)
    normalised = normalised.strip(".")  # remove leading/trailing dots

    original = raw if normalised != raw else None
    return normalised, original


def validate_source_ip(raw: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Validate *raw* as an IPv4 or IPv6 address using Python's stdlib.

    Returns:
        (valid_ip_str_or_None, original_if_nulled_else_None)
        None input → (None, None)  — no-op.
        Valid IP   → (ip, None)    — unchanged.
        Invalid IP → (None, raw)   — nulled, original preserved.
    """
    if raw is None:
        return None, None

    stripped = raw.strip()
    if not stripped:
        return None, raw

    try:
        # Raises ValueError for invalid addresses
        ipaddress.ip_address(stripped)
        return stripped, None
    except ValueError:
        return None, raw


# ---------------------------------------------------------------------------
# Composite normalizer
# ---------------------------------------------------------------------------

def normalize_event(event_in: SecurityEventCreate) -> SecurityEventCreate:
    """
    Apply all normalization rules to *event_in* and return a new
    SecurityEventCreate with canonical field values.

    If a field was changed/nulled its original value is recorded in
    ``attributes`` under a ``raw_*`` key so the full audit trail is preserved.

    The function is non-destructive: it always returns a new object (via
    model_copy) rather than mutating the input.
    """
    attrs = dict(event_in.attributes)  # shallow copy of existing attributes
    updates: dict = {}

    # --- severity ---
    norm_sev, raw_sev = normalize_severity(event_in.severity)
    updates["severity"] = norm_sev
    if raw_sev is not None:
        attrs["raw_severity"] = raw_sev

    # --- event_type ---
    norm_et, raw_et = normalize_event_type(event_in.event_type)
    updates["event_type"] = norm_et
    if raw_et is not None:
        attrs["raw_event_type"] = raw_et

    # --- source_ip ---
    norm_ip, raw_ip = validate_source_ip(event_in.source_ip)
    updates["source_ip"] = norm_ip
    if raw_ip is not None:
        attrs["raw_source_ip"] = raw_ip

    updates["attributes"] = attrs
    return event_in.model_copy(update=updates)
