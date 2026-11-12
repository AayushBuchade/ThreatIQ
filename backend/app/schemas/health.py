"""Pydantic Schemas for Health Check Endpoints."""

from typing import Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(..., description="Overall health status: ok | degraded | error")
    version: str = Field(..., description="Current platform version")
    database: str = Field(..., description="Database connection status: connected | disconnected")
    database_latency_ms: Optional[float] = Field(None, description="Database ping latency in milliseconds")
    response_time_ms: float = Field(..., description="Endpoint processing latency")
    timestamp: str = Field(..., description="UTC timestamp of the health check")

