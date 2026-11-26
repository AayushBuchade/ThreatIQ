"""Validated email analysis using the local PHISHGUARD classifier."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.logging import logger
from backend.app.db.session import get_db
from backend.app.schemas.email_analysis import EmailAnalysisRequest, EmailAnalysisResponse
from backend.app.services.phishguard.classifier import (
    PhishguardUnavailable,
    analyze_email,
    record_analysis,
)

router = APIRouter()


@router.post(
    "/email/analyze",
    response_model=EmailAnalysisResponse,
    tags=["Email"],
)
def analyze_email_endpoint(
    payload: EmailAnalysisRequest,
    db: Session = Depends(get_db),
) -> EmailAnalysisResponse:
    """Score one email. Recording uses the existing event pipeline and skips duplicates."""
    try:
        result = analyze_email(payload.subject, payload.sender, payload.body)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except PhishguardUnavailable as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    recorded = False
    duplicate = False
    event_id = None
    record_error = None
    if payload.record:
        try:
            event, duplicate = record_analysis(
                db, payload.subject, payload.sender, payload.body, result
            )
            recorded = not duplicate
            event_id = event.event_id
        except Exception as exc:
            logger.error(f"PHISHGUARD analysis could not be recorded: {exc}")
            record_error = "Analysis was computed but could not be recorded."

    return EmailAnalysisResponse(
        prediction=result["prediction"],
        predicted_class=result["predicted_class"],
        phishing_probability=result["phishing_probability"],
        model_version=result["model_version"],
        model_name=result["model_name"],
        sklearn_version=result["sklearn_version"],
        artifact_sha256=result["artifact_sha256"],
        token_contributions=result["token_contributions"],
        suspicious_urls=result.get("suspicious_urls") or [],
        attribution_note=result["attribution_note"],
        recorded=recorded,
        duplicate=duplicate,
        event_id=event_id,
        record_error=record_error,
    )
