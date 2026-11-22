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
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.logging import logger
from backend.app.models.security_event import SecurityEvent

MODEL_VERSION = "threatiq-iforest-1.0.0"
MIN_TRAINING_EVENTS = 25
MAX_HISTORY = 1000
N_ESTIMATORS = 100
RANDOM_STATE = 42
TOP_DEVIATIONS = 5
EVALUATION_LABEL_KEY = "evaluation_label"
SCORE_DIRECTION = (
    "model_score is the raw Isolation Forest decision_function value. "
    "Larger values are more normal. Smaller values are more anomalous. "
    "It is not a confidence percentage."
)

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
            "comparison": "statistical_z_score",
            "note": notes.get(name),
        })
    return evidence


def _top_deviations(evidence: list[dict]) -> list[dict]:
    """Largest |z| gaps versus the training distribution. Not SHAP values."""
    ranked = [item for item in evidence if item.get("z_score") is not None]
    ranked.sort(key=lambda item: abs(item["z_score"]), reverse=True)
    deviations = []
    for item in ranked[:TOP_DEVIATIONS]:
        z_score = item["z_score"]
        if z_score > 0:
            direction = "above_training_mean"
        elif z_score < 0:
            direction = "below_training_mean"
        else:
            direction = "at_training_mean"
        deviations.append({
            "name": item["name"],
            "value": item["value"],
            "training_mean": item["training_mean"],
            "z_score": z_score,
            "direction": direction,
            "comparison": "statistical_z_score",
            "explanation": "not_shap",
        })
    return deviations


def _fit_and_score(history: list[SecurityEvent], target: SecurityEvent):
    """Fit on chronological history only. `target` must not be in `history`."""
    ordered = sorted(
        history,
        key=lambda event: (_as_utc(event.created_at) or datetime.min.replace(tzinfo=timezone.utc), event.id or 0),
    )
    if any(event.event_id == target.event_id for event in ordered):
        raise ValueError("Training history includes the event being scored")
    matrix = np.asarray(
        [_feature_vector(event, ordered[:index]) for index, event in enumerate(ordered)],
        dtype=float,
    )
    target_vector = _feature_vector(target, ordered)
    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination="auto",
        random_state=RANDOM_STATE,
        n_jobs=1,
        bootstrap=False,
    )
    model.fit(matrix)
    features = np.asarray([target_vector], dtype=float)
    score = float(model.decision_function(features)[0])
    prediction = int(model.predict(features)[0])
    status = "anomalous" if prediction == -1 else "normal"
    return status, score, target_vector, matrix


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
        "top_deviations": [],
        "model_score": None,
        "score_direction": SCORE_DIRECTION,
        "deviation_method": "statistical_z_score",
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

    try:
        status, score, target_vector, matrix = _fit_and_score(history, target)
    except Exception as exc:
        logger.error(f"Isolation Forest scoring failed for {target.event_id}: {exc}")
        base.update({
            "evaluated": False,
            "status": "error",
            "detail": "Isolation Forest scoring failed. No anomaly decision was made.",
        })
        return base

    evidence = _evidence(target_vector, matrix, target)
    base.update({
        "evaluated": True,
        "status": status,
        "model_score": round(score, 6),
        "feature_evidence": evidence,
        "top_deviations": _top_deviations(evidence),
        "detail": (
            f"{SCORE_DIRECTION} This event was excluded from training. "
            "Feature deviations are statistical comparisons with the training mean, not SHAP values. "
            "The score is separate from severity and the stored threat score."
        ),
    })
    return base


def supplied_evaluation_label(event: SecurityEvent) -> Optional[str]:
    """Return an explicit evaluation label. Severity and threat_score are ignored."""
    attributes = event.attributes if isinstance(event.attributes, dict) else {}
    raw = attributes.get(EVALUATION_LABEL_KEY)
    if not isinstance(raw, str):
        return None
    value = raw.strip().lower()
    if value in {"normal", "anomalous"}:
        return value
    return None


def metrics_from_labels(y_true: list[str], y_pred: list[str]) -> dict:
    """
    Precision, recall, F1, and confusion matrix for supplied labels.

    Returns not_evaluated when no labels were supplied. The positive class is anomalous.
    """
    if not y_true or not y_pred or len(y_true) != len(y_pred):
        return {
            "status": "not_evaluated",
            "evaluated": False,
            "precision": None,
            "recall": None,
            "f1": None,
            "confusion_matrix": None,
            "positive_class": "anomalous",
            "detail": "No labeled predictions were supplied. Metrics were not calculated.",
        }
    y_true_bin = [1 if label == "anomalous" else 0 for label in y_true]
    y_pred_bin = [1 if label == "anomalous" else 0 for label in y_pred]
    matrix = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1]).tolist()
    return {
        "status": "evaluated",
        "evaluated": True,
        "precision": round(float(precision_score(y_true_bin, y_pred_bin, pos_label=1, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true_bin, y_pred_bin, pos_label=1, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true_bin, y_pred_bin, pos_label=1, zero_division=0)), 6),
        "confusion_matrix": {
            "labels": ["normal", "anomalous"],
            "matrix": matrix,
        },
        "positive_class": "anomalous",
        "detail": (
            "Precision, recall, and F1 use the supplied anomalous/normal labels. "
            "Rows are true normal, true anomalous. Columns are predicted normal, predicted anomalous."
        ),
    }


def _not_evaluated(detail: str, labeled_events: int = 0, unscored_events: int = 0) -> dict:
    return {
        "status": "not_evaluated",
        "evaluated": False,
        "precision": None,
        "recall": None,
        "f1": None,
        "confusion_matrix": None,
        "positive_class": "anomalous",
        "labeled_events": labeled_events,
        "scored_events": 0,
        "unscored_events": unscored_events,
        "excluded_from_training": [],
        "scored": [],
        "detail": detail,
    }


def evaluate_labeled_events(db: Session) -> dict:
    """
    Score stored events that carry an explicit evaluation_label.

    Labeled rows are the test set and are excluded from every training matrix.
    Training rows are earlier unlabeled events only.
    """
    stmt = select(SecurityEvent).order_by(SecurityEvent.created_at.asc(), SecurityEvent.id.asc())
    events = list(db.execute(stmt).scalars().all())
    events.sort(
        key=lambda event: (
            _as_utc(event.created_at) or datetime.min.replace(tzinfo=timezone.utc),
            event.id or 0,
        )
    )
    labeled = [(event, supplied_evaluation_label(event)) for event in events]
    labeled = [(event, label) for event, label in labeled if label is not None]
    labeled_ids = {event.event_id for event, _label in labeled}
    if not labeled:
        return _not_evaluated(
            "No stored evaluation_label values of normal or anomalous. "
            "Severity and threat_score are not labels. Metrics were not calculated."
        )

    y_true: list[str] = []
    y_pred: list[str] = []
    scored = []
    unscored = 0
    try:
        for event, label in labeled:
            history = [
                row for row in events
                if _is_before(row, event) and row.event_id not in labeled_ids
            ]
            if len(history) > MAX_HISTORY:
                history = history[-MAX_HISTORY:]
            if event.created_at is None or len(history) < MIN_TRAINING_EVENTS:
                unscored += 1
                continue
            status, score, _vector, _matrix = _fit_and_score(history, event)
            y_true.append(label)
            y_pred.append(status)
            scored.append({
                "event_id": event.event_id,
                "label": label,
                "prediction": status,
                "model_score": round(score, 6),
                "training_events": len(history),
            })
    except Exception as exc:
        logger.error(f"Labeled anomaly evaluation failed: {exc}")
        return {
            "status": "error",
            "evaluated": False,
            "precision": None,
            "recall": None,
            "f1": None,
            "confusion_matrix": None,
            "positive_class": "anomalous",
            "labeled_events": len(labeled),
            "scored_events": 0,
            "unscored_events": unscored,
            "excluded_from_training": sorted(labeled_ids),
            "scored": [],
            "detail": "Labeled evaluation failed. Metrics were not calculated.",
        }

    if not y_true:
        return _not_evaluated(
            "Labeled events were found, but none had enough earlier unlabeled events to score. "
            "Metrics were not calculated.",
            labeled_events=len(labeled),
            unscored_events=unscored,
        ) | {"excluded_from_training": sorted(labeled_ids)}

    metrics = metrics_from_labels(y_true, y_pred)
    metrics.update({
        "labeled_events": len(labeled),
        "scored_events": len(scored),
        "unscored_events": unscored,
        "excluded_from_training": sorted(labeled_ids),
        "scored": scored,
        "detail": (
            f"{metrics['detail']} Each scored event was trained only on earlier unlabeled events. "
            "Every labeled event was excluded from training."
        ),
    })
    return metrics
