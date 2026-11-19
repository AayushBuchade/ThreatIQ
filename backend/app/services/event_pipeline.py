"""
ThreatIQ Security Event Pipeline Service
Manages event persistence, database transactions, and telemetry queries.
"""

import uuid
import time
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, desc, func
from backend.app.models.security_event import SecurityEvent
from backend.app.schemas.security_event import SecurityEventCreate
from backend.app.core.logging import logger
from backend.app.core.normalization import normalize_event
from backend.app.services.redis_streams import publish_normalized_event


class EventPipelineService:
    """Handles ingestion and database persistence of security events."""

    @staticmethod
    def ingest_event(
        db: Session,
        event_in: SecurityEventCreate,
        threat_score: float = 0.0
    ) -> Tuple[SecurityEvent, float]:
        """
        Persists a security event to PostgreSQL/SQLite, measuring DB write latency.
        Returns the saved model and roundtrip latency in ms.
        """
        # Normalise field values before persistence
        event_in = normalize_event(event_in)

        start_time = time.perf_counter()
        event_uuid = f"tiq-{uuid.uuid4().hex[:12]}"

        db_event = SecurityEvent(
            event_id=event_uuid,
            event_type=event_in.event_type,
            severity=event_in.severity,
            source_ip=event_in.source_ip,
            destination_ip=event_in.destination_ip,
            threat_score=threat_score,
            status="ingested",
            message=event_in.message,
            attributes=event_in.attributes
        )

        db.add(db_event)
        db.commit()
        db.refresh(db_event)

        roundtrip_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.info(
            f"Security event persisted: {db_event.event_id} ({db_event.event_type}) in {roundtrip_ms}ms"
        )
        # Single publish path for REST, UDP, and TCP. Best-effort only:
        # Redis failures are logged and do not undo the committed row.
        publish_normalized_event(db_event)
        return db_event, roundtrip_ms

    @staticmethod
    def get_recent_events(
        db: Session,
        limit: int = 15,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """Queries the most recent security events from database ordered by created_at desc.

        Optional filters:
            severity  — exact match (case-insensitive)
            event_type — substring match (case-insensitive)
            source_ip  — exact match
        """
        stmt = select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(limit)

        if severity is not None:
            stmt = stmt.where(func.lower(SecurityEvent.severity) == severity.strip().lower())

        if event_type is not None:
            stmt = stmt.where(func.lower(SecurityEvent.event_type).contains(event_type.strip().lower()))

        if source_ip is not None:
            stmt = stmt.where(SecurityEvent.source_ip == source_ip.strip())

        result = db.execute(stmt)
        return list(result.scalars().all())
