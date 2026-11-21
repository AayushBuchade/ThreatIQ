"""
ThreatIQ Security Event Pipeline Service
Manages event persistence, database transactions, and telemetry queries.
"""

import uuid
import time
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, desc, func, or_
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
    def _apply_event_filters(
        stmt,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        q: Optional[str] = None,
    ):
        """Shared WHERE clause for the recent page and the unpaged summary."""
        if severity is not None:
            stmt = stmt.where(func.lower(SecurityEvent.severity) == severity.strip().lower())

        if event_type is not None:
            stmt = stmt.where(
                func.lower(SecurityEvent.event_type).contains(event_type.strip().lower())
            )

        if source_ip is not None:
            stmt = stmt.where(SecurityEvent.source_ip == source_ip.strip())

        if q is not None and q.strip():
            escaped = (
                q.strip()
                .lower()
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            pattern = f"%{escaped}%"
            stmt = stmt.where(
                or_(
                    func.lower(SecurityEvent.event_id).like(pattern, escape="\\"),
                    func.lower(SecurityEvent.event_type).like(pattern, escape="\\"),
                    func.lower(SecurityEvent.message).like(pattern, escape="\\"),
                    func.lower(func.coalesce(SecurityEvent.source_ip, "")).like(pattern, escape="\\"),
                    func.lower(func.coalesce(SecurityEvent.destination_ip, "")).like(
                        pattern, escape="\\"
                    ),
                )
            )
        return stmt

    @staticmethod
    def get_recent_events(
        db: Session,
        limit: int = 15,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        q: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """Queries the most recent security events from database ordered by created_at desc.

        Optional filters:
            severity  — exact match (case-insensitive)
            event_type — substring match (case-insensitive)
            source_ip  — exact match
            q — substring match across id, type, message, and IP fields
        """
        stmt = select(SecurityEvent)
        stmt = EventPipelineService._apply_event_filters(
            stmt,
            severity=severity,
            event_type=event_type,
            source_ip=source_ip,
            q=q,
        )
        stmt = stmt.order_by(desc(SecurityEvent.created_at)).limit(limit)
        result = db.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    def get_event_summary(
        db: Session,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        q: Optional[str] = None,
    ) -> dict:
        """Count stored events. This is not limited to the recent-events page."""
        stmt = select(SecurityEvent.severity, func.count(SecurityEvent.id))
        stmt = EventPipelineService._apply_event_filters(
            stmt,
            severity=severity,
            event_type=event_type,
            source_ip=source_ip,
            q=q,
        )
        stmt = stmt.group_by(SecurityEvent.severity)
        rows = db.execute(stmt).all()

        by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0, "other": 0}
        total = 0
        for severity_value, count in rows:
            amount = int(count)
            total += amount
            key = (severity_value or "").strip().lower()
            if key in ("low", "medium", "high", "critical"):
                by_severity[key] += amount
            else:
                by_severity["other"] += amount
        return {"total": total, "by_severity": by_severity}
