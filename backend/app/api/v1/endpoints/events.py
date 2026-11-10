"""
Security Event Ingestion & Integration Test Endpoints
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from backend.app.db.session import get_db
from backend.app.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventResponse,
    TestPingResponse,
    RecentEventsResponse,
)
from backend.app.services.event_pipeline import EventPipelineService

router = APIRouter()


@router.post(
    "/events/test-ping",
    response_model=TestPingResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Events"]
)
def test_ping_event(
    event_in: SecurityEventCreate,
    db: Session = Depends(get_db)
) -> TestPingResponse:
    """
    Executes a verified frontend -> backend -> database integration test.
    Validates input schema, writes to PostgreSQL/SQLite, commits, and returns verified record with latency.
    """
    saved_event, roundtrip_ms = EventPipelineService.ingest_event(
        db=db,
        event_in=event_in,
        threat_score=15.0 if event_in.severity == "low" else (50.0 if event_in.severity == "medium" else 85.0)
    )

    return TestPingResponse(
        success=True,
        event_id=saved_event.event_id,
        db_roundtrip_ms=roundtrip_ms,
        persisted_event=SecurityEventResponse.model_validate(saved_event),
        message="Full-stack integration verified: payload persisted and queried from database."
    )


@router.post(
    "/events/ingest",
    response_model=SecurityEventResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Events"]
)
def ingest_event(
    event_in: SecurityEventCreate,
    db: Session = Depends(get_db)
) -> SecurityEventResponse:
    """Standard event ingestion endpoint."""
    saved_event, _ = EventPipelineService.ingest_event(db=db, event_in=event_in)
    return SecurityEventResponse.model_validate(saved_event)


@router.get(
    "/events/recent",
    response_model=RecentEventsResponse,
    tags=["Events"]
)
def get_recent_events(
    limit: int = 15,
    db: Session = Depends(get_db)
) -> RecentEventsResponse:
    """Returns recent events persisted in database."""
    events = EventPipelineService.get_recent_events(db=db, limit=limit)
    return RecentEventsResponse(
        total=len(events),
        events=[SecurityEventResponse.model_validate(e) for e in events]
    )
