"""
ThreatIQ Security Event Pipeline Service
Manages event persistence, database transactions, and telemetry queries.
"""

import uuid
import time
from typing import List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, desc
from backend.app.models.security_event import SecurityEvent
from backend.app.schemas.security_event import SecurityEventCreate
from backend.app.core.logging import logger


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
        return db_event, roundtrip_ms

    @staticmethod
    def get_recent_events(
        db: Session,
        limit: int = 15
    ) -> List[SecurityEvent]:
        """Queries the most recent security events from database ordered by created_at desc."""
        stmt = select(SecurityEvent).order_by(desc(SecurityEvent.created_at)).limit(limit)
        result = db.execute(stmt)
        return list(result.scalars().all())
