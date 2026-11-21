"""
On-demand Isolation Forest assessment for one stored security event.

The model is fit only on earlier events. The event being scored is never a
training row. When fewer than MIN_TRAINING_EVENTS earlier rows exist, the
service returns insufficient_data and does not invent a normal or anomalous
decision. The result is not written to severity or threat_score.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.security_event import SecurityEvent

MODEL_VERSION = "threatiq-iforest-1.0.0"
MIN_TRAINING_EVENTS = 25
MAX_HISTORY = 1000
N_ESTIMATORS = 100
RANDOM_STATE = 42

_WINDOW_15 = timedelta(minutes=15)
_WINDOW_60 = timedelta(minutes=60)

FEATURE_NAMES = (
    "hour_sin",
    "hour_cos",
    "weekday_sin",
    "weekday_cos",
    "prior_events_15m",
    "prior_events_60m",
    "same_source_events_15m",
    "same_source_failed_logins_15m",
    "event_is_failed_login",
    "has_source_ip",
    "prior_same_event_type",
    "distinct_source_ips_15m",
)


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _is_failed_login(event: SecurityEvent) -> bool:
    event_type = (event.event_type or "").lower()
    message = (event.message or "").lower()
    if "login.failed" in event_type or "failed_login" in event_type:
        return True
    if "failed password" in message or "failed login" in message or "login failure" in message:
        return True
    return False


def _is_before(event: SecurityEvent, target: SecurityEvent) -> bool:
    if event.event_id == target.event_id:
        return False
    event_time = _as_utc(event.created_at)
    target_time = _as_utc(target.created_at)
    if event_time is None or target_time is None:
        return False
    if event_time < target_time:
        return True
    if event_time == target_time and event.id is not None and target.id is not None:
        return event.id < target.id
    return False


def _feature_vector(event: SecurityEvent, history: list[SecurityEvent]) -> list[float]:
    """Numeric features for one event. `history` must not include that event."""
    event_time = _as_utc(event.created_at)
    if event_time is None:
        hour = 0.0
        weekday = 0.0
    else:
        hour = event_time.hour + (event_time.minute / 60.0)
        weekday = float(event_time.weekday())

    hour_angle = 2.0 * math.pi * hour / 24.0
    weekday_angle = 2.0 * math.pi * weekday / 7.0
    source_ip = (event.source_ip or "").strip()
    event_type = (event.event_type or "").strip().lower()
    failed_login = _is_failed_login(event)

    prior_15 = []
    prior_60 = []
    if event_time is not None:
        start_15 = event_time - _WINDOW_15
        start_60 = event_time - _WINDOW_60
        for earlier in history:
            earlier_time = _as_utc(earlier.created_at)
            if earlier_time is None or earlier_time >= event_time:
                continue
            if earlier_time >= start_60:
                prior_60.append(earlier)
            if earlier_time >= start_15:
                prior_15.append(earlier)

    same_source_15 = [row for row in prior_15 if (row.source_ip or "").strip() == source_ip] if source_ip else []
    same_type = [
        row for row in history
        if (row.event_type or "").strip().lower() == event_type
    ]
    distinct_ips = {
        (row.source_ip or "").strip()
        for row in prior_15
        if (row.source_ip or "").strip()
    }

    return [
        math.sin(hour_angle),
        math.cos(hour_angle),
        math.sin(weekday_angle),
        math.cos(weekday_angle),
        float(len(prior_15)),
        float(len(prior_60)),
        float(len(same_source_15)),
        float(sum(1 for row in same_source_15 if _is_failed_login(row))),
        1.0 if failed_login else 0.0,
        1.0 if source_ip else 0.0,
        float(len(same_type)),
        float(len(distinct_ips)),
    ]


def _history_before(db: Session, target: SecurityEvent) -> list[SecurityEvent]:
    stmt = select(SecurityEvent).order_by(SecurityEvent.created_at.asc(), SecurityEvent.id.asc())
    rows = list(db.execute(stmt).scalars().all())
    prior = [row for row in rows if _is_before(row, target)]
    if len(prior) > MAX_HISTORY:
        prior = prior[-MAX_HISTORY:]
    return prior


def _evidence(vector: list[float], matrix: np.ndarray, event: SecurityEvent) -> list[dict]:
    means = matrix.mean(axis=0)
    stds = matrix.std(axis=0)
    source_ip = (event.source_ip or "").strip()
    notes = {
        "same_source_events_15m": None if source_ip else "No source IP on this event, so same-IP counts are zero.",
        "same_source_failed_logins_15m": None if source_ip else "No source IP on this event, so same-IP counts are zero.",
        "prior_events_15m": "Events in the 15 minutes before this one, excluding this event.",
        "prior_events_60m": "Events in the 60 minutes before this one, excluding this event.",
        "prior_same_event_type": "Earlier events with the same event type. This event is not included.",
        "event_is_failed_login": "1 when the event type or message is a failed login.",
    }
    evidence = []
    for index, name in enumerate(FEATURE_NAMES):
        std = float(stds[index])
        z_score = None if std < 1e-9 else round((vector[index] - float(means[index])) / std, 4)
        evidence.append({
            "name": name,
            "value": round(float(vector[index]), 6),
            "training_mean": round(float(means[index]), 6),
            "z_score": z_score,
            "note": notes.get(name),
        })
    return evidence


def assess_event(db: Session, event_id: str) -> Optional[dict]:
    """
    Score one stored event.

    Returns None when the event id is unknown. Does not update the row.
    """
    target = db.execute(
        select(SecurityEvent).where(SecurityEvent.event_id == event_id)
    ).scalar_one_or_none()
    if target is None:
        return None

    history = _history_before(db, target)
    base = {
        "event_id": target.event_id,
        "model_version": MODEL_VERSION,
        "training_events": len(history),
        "minimum_training_events": MIN_TRAINING_EVENTS,
        "feature_evidence": [],
        "model_score": None,
    }
    if target.created_at is None or len(history) < MIN_TRAINING_EVENTS:
        base.update({
            "evaluated": False,
            "status": "insufficient_data",
            "detail": (
                f"Need at least {MIN_TRAINING_EVENTS} earlier events to fit Isolation Forest. "
                f"Found {len(history)}. No anomaly decision was made."
            ),
        })
        return base

    matrix_rows = []
    for index, earlier in enumerate(history):
        matrix_rows.append(_feature_vector(earlier, history[:index]))
    matrix = np.asarray(matrix_rows, dtype=float)
    target_vector = _feature_vector(target, history)

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination="auto",
        random_state=RANDOM_STATE,
        n_jobs=1,
        bootstrap=False,
    )
    model.fit(matrix)
    score = float(model.decision_function(np.asarray([target_vector], dtype=float))[0])
    prediction = int(model.predict(np.asarray([target_vector], dtype=float))[0])
    status = "anomalous" if prediction == -1 else "normal"
    base.update({
        "evaluated": True,
        "status": status,
        "model_score": round(score, 6),
        "feature_evidence": _evidence(target_vector, matrix, target),
        "detail": (
            "Isolation Forest decision_function score. Higher values are more normal "
            "under scikit-learn. This event was excluded from training. "
            "The score is separate from severity and the stored threat score."
        ),
    })
    return base
