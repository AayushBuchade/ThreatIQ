"""
Load the serialized PHISHGUARD classifier and score one email.

Training fit TF-IDF on clean_text() output, not the stopword-filtered
preprocess_for_tfidf() string. This module follows that same input.
"""

from __future__ import annotations

import hashlib
import json
import warnings
from functools import lru_cache
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn import __version__ as sklearn_version
from sklearn.exceptions import InconsistentVersionWarning
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.logging import logger
from backend.app.models.security_event import SecurityEvent
from backend.app.schemas.security_event import SecurityEventCreate
from backend.app.services.event_pipeline import EventPipelineService
from backend.app.services.phishguard.text_preprocessor import clean_text
from backend.app.services.phishguard.url_inspector import suspicious_urls

MODEL_DIR = Path(__file__).resolve().parents[2] / "ml_models" / "phishing"
MODEL_PATH = MODEL_DIR / "best_model.joblib"
VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.joblib"
METADATA_PATH = MODEL_DIR / "model_metadata.json"

# SHA-256 of the copied upstream artifacts. A mismatch refuses to score.
EXPECTED_SHA256 = {
    "best_model.joblib": "7cdbf8d5f471b35da18eecbc0ea967cfd5791804090dac656e08eea7baf108ad",
    "tfidf_vectorizer.joblib": "0cf16ed6969616104b712c78fd4a3a3e48721e515677f4491e9c804c7ec0e907",
}

MODEL_VERSION = "phishguard-linearsvc-calibrated@2026-10-10"
EVENT_TYPE = "email.phishing.analysis"
ATTRIBUTION_NOTE = (
    "Token contributions are TF-IDF value multiplied by the calibrated LinearSVC coefficient. "
    "They are not SHAP values."
)


class PhishguardUnavailable(RuntimeError):
    """The serialized model cannot be used. No prediction was produced."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_artifact(path: Path) -> None:
    if not path.is_file():
        raise PhishguardUnavailable(f"Missing PHISHGUARD artifact: {path.name}")
    actual = _sha256(path)
    expected = EXPECTED_SHA256[path.name]
    if actual != expected:
        raise PhishguardUnavailable(
            f"SHA-256 mismatch for {path.name}. Refusing to score with an unexpected artifact."
        )


def _load_joblib(path: Path):
    """Load one artifact. A sklearn version mismatch becomes an error."""
    _verify_artifact(path)
    with warnings.catch_warnings():
        warnings.filterwarnings("error", category=InconsistentVersionWarning)
        try:
            return joblib.load(path)
        except InconsistentVersionWarning as exc:
            raise PhishguardUnavailable(
                "PHISHGUARD artifact is incompatible with the installed scikit-learn. "
                "No prediction was produced."
            ) from exc
        except Exception as exc:
            raise PhishguardUnavailable(
                f"Could not load {path.name}. No prediction was produced."
            ) from exc


@lru_cache(maxsize=1)
def load_models():
    model = _load_joblib(MODEL_PATH)
    vectorizer = _load_joblib(VECTORIZER_PATH)
    if not hasattr(model, "predict_proba"):
        raise PhishguardUnavailable("Loaded model has no predict_proba. No prediction was produced.")
    return model, vectorizer


def model_metadata() -> dict:
    if not METADATA_PATH.is_file():
        return {}
    try:
        return json.loads(METADATA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def compose_model_input(subject: str, sender: str, body: str) -> str:
    parts = [part.strip() for part in (subject, sender, body) if part and part.strip()]
    return "\n".join(parts)


def analysis_fingerprint(model_input: str) -> str:
    return hashlib.sha256(model_input.encode("utf-8")).hexdigest()


def _linear_weights(model) -> Optional[np.ndarray]:
    if hasattr(model, "coef_"):
        return np.asarray(model.coef_[0])
    calibrated = getattr(model, "calibrated_classifiers_", None)
    if not calibrated:
        return None
    weights = []
    for item in calibrated:
        base = getattr(item, "estimator", None) or getattr(item, "base_estimator", None)
        if base is not None and hasattr(base, "coef_"):
            weights.append(np.asarray(base.coef_[0]))
    if not weights:
        return None
    return np.mean(weights, axis=0)


def _token_contributions(model, vectorizer, matrix, limit: int = 8) -> list[dict]:
    weights = _linear_weights(model)
    if weights is None:
        return []
    names = vectorizer.get_feature_names_out()
    contributions = []
    for index in matrix.nonzero()[1]:
        tfidf = float(matrix[0, index])
        weight = float(weights[index])
        contributions.append({
            "token": str(names[index]),
            "tfidf": round(tfidf, 6),
            "weight": round(weight, 6),
            "contribution": round(tfidf * weight, 6),
            "method": "tfidf_linear_weight",
        })
    contributions.sort(key=lambda item: abs(item["contribution"]), reverse=True)
    return contributions[:limit]


def _safe_urls(text: str) -> list[dict]:
    try:
        return suspicious_urls(text)
    except Exception as exc:
        logger.error(f"URL inspection failed: {exc}")
        return []


def analyze_email(subject: str, sender: str, body: str) -> dict:
    """
    Score one email with the real calibrated Linear SVM.

    Raises PhishguardUnavailable when the artifact cannot be used.
    Raises ValueError when preprocessing leaves no text.
    """
    model_input = compose_model_input(subject, sender, body)
    cleaned = clean_text(model_input)
    if not cleaned:
        raise ValueError("Nothing remained after PHISHGUARD preprocessing.")

    model, vectorizer = load_models()
    try:
        matrix = vectorizer.transform([cleaned])
        probabilities = model.predict_proba(matrix)[0]
        classes = [int(label) for label in model.classes_]
        predicted = int(model.predict(matrix)[0])
    except PhishguardUnavailable:
        raise
    except Exception as exc:
        logger.error(f"PHISHGUARD inference failed: {exc}")
        raise PhishguardUnavailable("Email analysis failed. No prediction was produced.") from exc

    if 1 not in classes or len(probabilities) != len(classes):
        raise PhishguardUnavailable("Model class layout is unexpected. No prediction was produced.")

    phishing_probability = float(probabilities[classes.index(1)])
    label = "phishing" if predicted == 1 else "legitimate"
    metadata = model_metadata()
    return {
        "prediction": label,
        "predicted_class": predicted,
        "phishing_probability": round(phishing_probability, 6),
        "model_version": MODEL_VERSION,
        "model_name": metadata.get("best_model_name") or "Linear SVM (Calibrated)",
        "sklearn_version": sklearn_version,
        "artifact_sha256": EXPECTED_SHA256["best_model.joblib"],
        "preprocessed_text": cleaned,
        "analysis_fingerprint": analysis_fingerprint(model_input),
        "token_contributions": _token_contributions(model, vectorizer, matrix),
        "suspicious_urls": _safe_urls(model_input),
        "attribution_note": ATTRIBUTION_NOTE,
    }


def find_recorded_analysis(db: Session, fingerprint: str) -> Optional[SecurityEvent]:
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.event_type == EVENT_TYPE)
        .order_by(SecurityEvent.id.asc())
    )
    for event in db.execute(stmt).scalars():
        attributes = event.attributes if isinstance(event.attributes, dict) else {}
        if attributes.get("analysis_fingerprint") == fingerprint:
            return event
    return None


def record_analysis(db: Session, subject: str, sender: str, body: str, result: dict) -> tuple[SecurityEvent, bool]:
    """
    Persist the analysis through the existing event pipeline.

    Returns the stored row and whether it already existed.
    """
    existing = find_recorded_analysis(db, result["analysis_fingerprint"])
    if existing is not None:
        return existing, True

    preview = body.strip().replace("\n", " ")
    if len(preview) > 240:
        preview = preview[:240] + "…"
    message = preview or subject.strip() or "Email analysis"
    probability = float(result["phishing_probability"])
    event_in = SecurityEventCreate(
        event_type=EVENT_TYPE,
        severity="high" if result["prediction"] == "phishing" else "low",
        source_ip=None,
        message=message,
        attributes={
            "analysis_fingerprint": result["analysis_fingerprint"],
            "prediction": result["prediction"],
            "phishing_probability": probability,
            "model_version": result["model_version"],
            "artifact_sha256": result["artifact_sha256"],
            "subject": subject.strip(),
            "sender": sender.strip(),
            "suspicious_urls": result.get("suspicious_urls") or [],
            "score_basis": "threat_score is the calibrated phishing probability multiplied by 100.",
        },
    )
    saved, _latency = EventPipelineService.ingest_event(
        db,
        event_in,
        threat_score=round(probability * 100.0, 2),
    )
    return saved, False
