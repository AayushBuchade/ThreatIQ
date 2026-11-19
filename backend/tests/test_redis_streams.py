"""
Best-effort Redis Streams publishing after database persistence.

Covers the single ingest path used by REST, UDP, and TCP:
  - enabled Redis accepts one XADD carrying event_id
  - a Redis failure leaves the database row in place
  - disabled mode does not open a Redis connection
"""

import logging
from unittest.mock import MagicMock

import redis
from sqlalchemy import select

from backend.app.core.config import settings
from backend.app.models.security_event import SecurityEvent
from backend.app.schemas.security_event import SecurityEventCreate
from backend.app.services.event_pipeline import EventPipelineService


def _sample_event() -> SecurityEventCreate:
    return SecurityEventCreate(
        event_type="auth.login.failed",
        severity="high",
        source_ip="203.0.113.10",
        destination_ip="198.51.100.4",
        message="normalized event for redis stream test",
    )


def _enable_streams(monkeypatch, stream_name: str = "threatiq:events:normalized") -> None:
    monkeypatch.setattr(settings, "REDIS_STREAMS_ENABLED", True)
    monkeypatch.setattr(settings, "REDIS_URL", "redis://127.0.0.1:6379/0")
    monkeypatch.setattr(settings, "REDIS_STREAM_NAME", stream_name)


def test_publish_succeeds_with_event_id_after_persist(db_session, monkeypatch):
    _enable_streams(monkeypatch)
    mock_client = MagicMock()
    mock_client.xadd.return_value = "1-0"
    from_url = MagicMock(return_value=mock_client)
    monkeypatch.setattr("backend.app.services.redis_streams.redis.Redis.from_url", from_url)

    saved, latency_ms = EventPipelineService.ingest_event(db_session, _sample_event())

    assert latency_ms >= 0.0
    assert saved.event_id.startswith("tiq-")
    from_url.assert_called_once()
    assert from_url.call_args.kwargs["socket_timeout"] <= 1
    assert from_url.call_args.kwargs["socket_connect_timeout"] <= 1

    mock_client.xadd.assert_called_once()
    stream_name, fields = mock_client.xadd.call_args.args
    assert stream_name == "threatiq:events:normalized"
    assert fields["event_id"] == saved.event_id
    assert fields["event_type"] == "auth.login.failed"
    assert fields["severity"] == "high"
    assert fields["source_ip"] == "203.0.113.10"
    mock_client.close.assert_called_once()

    row = db_session.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == saved.event_id)
    ).scalar_one()
    assert row.message == "normalized event for redis stream test"


def test_redis_failure_keeps_database_row(db_session, monkeypatch, caplog):
    _enable_streams(monkeypatch)
    mock_client = MagicMock()
    mock_client.xadd.side_effect = redis.exceptions.ConnectionError("redis unavailable")
    monkeypatch.setattr(
        "backend.app.services.redis_streams.redis.Redis.from_url",
        MagicMock(return_value=mock_client),
    )

    with caplog.at_level(logging.ERROR, logger="threatiq"):
        saved, _ = EventPipelineService.ingest_event(db_session, _sample_event())

    assert saved.event_id.startswith("tiq-")
    assert any("Redis Streams publish failed" in record.message for record in caplog.records)
    assert any("not guaranteed" in record.message for record in caplog.records)

    row = db_session.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == saved.event_id)
    ).scalar_one()
    assert row.severity == "high"
    mock_client.xadd.assert_called_once()


def test_redis_disabled_does_not_connect(db_session, monkeypatch):
    monkeypatch.setattr(settings, "REDIS_STREAMS_ENABLED", False)
    from_url = MagicMock()
    monkeypatch.setattr("backend.app.services.redis_streams.redis.Redis.from_url", from_url)

    saved, _ = EventPipelineService.ingest_event(db_session, _sample_event())

    assert saved.event_id.startswith("tiq-")
    from_url.assert_not_called()
    row = db_session.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == saved.event_id)
    ).scalar_one()
    assert row.event_type == "auth.login.failed"
