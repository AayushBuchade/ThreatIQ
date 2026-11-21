"""Pydantic Schemas for Security Event Ingestion, Persistence, and Triage."""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class SecurityEventCreate(BaseModel):
    event_type: str = Field(..., json_schema_extra={"example": "auth.login.failed"}, description="Dot-separated event category")
    severity: str = Field("medium", json_schema_extra={"example": "high"}, description="low | medium | high | critical")
    source_ip: Optional[str] = Field(None, json_schema_extra={"example": "192.168.1.100"})
    destination_ip: Optional[str] = Field(None, json_schema_extra={"example": "10.0.0.5"})
    message: str = Field(..., json_schema_extra={"example": "Failed password attempt for root"})
    attributes: Dict[str, Any] = Field(default_factory=dict)


class SecurityEventResponse(BaseModel):
    id: int
    event_id: str
    event_type: str
    severity: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    threat_score: float
    status: str
    message: str
    attributes: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TestPingResponse(BaseModel):
    success: bool
    event_id: str
    db_roundtrip_ms: float
    persisted_event: SecurityEventResponse
    message: str


class RecentEventsResponse(BaseModel):
    total: int
    events: List[SecurityEventResponse]


class EventSummaryResponse(BaseModel):
    """Database counts. Independent of the recent-events page size."""

    total: int
    by_severity: Dict[str, int]


class FeatureEvidence(BaseModel):
    name: str
    value: float
    training_mean: float
    z_score: Optional[float] = None
    note: Optional[str] = None


class AnomalyAssessmentResponse(BaseModel):
    """Isolation Forest result. Not a severity and not the stored threat score."""

    event_id: str
    evaluated: bool
    status: str
    model_score: Optional[float] = None
    model_version: str
    training_events: int
    minimum_training_events: int
    feature_evidence: List[FeatureEvidence] = Field(default_factory=list)
    detail: str
