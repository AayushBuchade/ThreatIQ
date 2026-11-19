"""
Best-effort Redis Streams publisher for normalized security events.

Called from EventPipelineService only, after the database commit succeeds.
REST, UDP, and TCP ingestion share that one path so an event is not published
twice.

This is not guaranteed delivery. There is no outbox and no retry loop. If the
process crashes after commit and before XADD, or if Redis is down, the stream
entry can be missing while the database row remains. Consumers deduplicate
with the published event_id.
"""

from __future__ import annotations

import redis

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.models.security_event import SecurityEvent

# Short enough that a down Redis cannot stall ingestion.
_SOCKET_TIMEOUT_SECONDS = 0.5


def publish_normalized_event(event: SecurityEvent) -> bool:
    """
    Append one normalized event to the configured Redis stream.

    Returns True only when XADD completed. Returns False when publishing is
    disabled, misconfigured, or Redis failed. Never raises.
    """
    if not settings.REDIS_STREAMS_ENABLED:
        return False

    stream_name = (settings.REDIS_STREAM_NAME or "").strip()
    redis_url = (settings.REDIS_URL or "").strip()
    event_id = (event.event_id or "").strip()
    if not stream_name or not redis_url or not event_id:
        logger.error(
            "Redis Streams publish skipped: stream name, Redis URL, or event_id is empty. "
            "Database row was kept. Delivery is not guaranteed."
        )
        return False

    client = None
    try:
        client = redis.Redis.from_url(
            redis_url,
            socket_timeout=_SOCKET_TIMEOUT_SECONDS,
            socket_connect_timeout=_SOCKET_TIMEOUT_SECONDS,
            decode_responses=True,
        )
        client.xadd(
            stream_name,
            {
                "event_id": event_id,
                "event_type": event.event_type or "",
                "severity": event.severity or "",
                "source_ip": event.source_ip or "",
                "destination_ip": event.destination_ip or "",
                "threat_score": str(event.threat_score if event.threat_score is not None else 0.0),
                "status": event.status or "",
                "message": event.message or "",
            },
        )
        logger.info(
            f"Published event {event_id} to Redis stream {stream_name}. "
            "Best-effort only; no outbox."
        )
        return True
    except Exception as exc:
        logger.error(
            f"Redis Streams publish failed for event {event_id}; database row was kept. "
            f"Delivery is not guaranteed: {exc}"
        )
        return False
    finally:
        if client is not None:
            try:
                client.close()
            except Exception as exc:
                logger.error(f"Redis client close failed after publishing {event_id}: {exc}")
