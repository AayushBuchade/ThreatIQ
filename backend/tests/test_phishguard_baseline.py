"""
Test Suite for PhishGuard Asset Integrity & Deserialization Baseline
Verifies that serialized joblib artifacts from PHISHGUARD are compatible with
ThreatIQ's runtime environment (Python 3.13 / Scikit-learn).
"""

import os
import joblib
import pytest

PHISHGUARD_DIR = os.path.abspath(
    os.path.join(
        os.path.expanduser("~"),
        ".gemini/antigravity/brain/3532395e-8e28-443d-96d1-7391bf1de752/scratch/PHISHGUARD"
    )
)


@pytest.mark.skipif(
    not os.path.exists(os.path.join(PHISHGUARD_DIR, "models/best_model.joblib")),
    reason="PHISHGUARD scratch clone not available"
)
def test_phishguard_model_artifact_deserialization():
    """Validates that best_model.joblib and tfidf_vectorizer.joblib deserialize cleanly."""
    model_path = os.path.join(PHISHGUARD_DIR, "models/best_model.joblib")
    vectorizer_path = os.path.join(PHISHGUARD_DIR, "models/tfidf_vectorizer.joblib")

    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)

    assert model is not None
    assert vectorizer is not None

    # Test sample vector transformation and inference
    test_sample = ["URGENT: Your account has been suspended. Click here to verify."]
    vec = vectorizer.transform(test_sample)
    assert vec.shape[1] == 5000  # Verified vocabulary size

    probs = model.predict_proba(vec)[0]
    assert len(probs) == 2
    assert 0.0 <= probs[1] <= 1.0
    # Phishing probability for this urgent threat phrase should be high
    assert probs[1] > 0.5

