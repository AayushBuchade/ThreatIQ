"""
Health Check API Endpoint
Returns operational status and verifies database connectivity with measured latency.
"""

import time
from datetime import datetime, timezone
from fastapi import APIRouter
from backend.app.schemas.health import HealthResponse
from backend.app.core.config import settings
from backend.app.db.session import check_db_connection

router = APIRouter()


@router.get("/health", response_model=HealthResponse, tags=["Health"])
def health_check() -> HealthResponse:
    """
    Evaluates backend service health and tests live database connectivity.
    """
    start_time = time.perf_counter()
    db_check = check_db_connection()
    response_time = (time.perf_counter() - start_time) * 1000.0

    overall_status = "ok" if db_check["status"] == "connected" else "degraded"

    return HealthResponse(
        status=overall_status,
        version=settings.VERSION,
        database=db_check["status"],
        database_latency_ms=db_check.get("latency_ms"),
        response_time_ms=round(response_time, 2),
        timestamp=datetime.now(timezone.utc).isoformat()
    )
