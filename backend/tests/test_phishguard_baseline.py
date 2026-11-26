"""PHISHGUARD artifacts must load on the pinned scikit-learn release."""

import warnings

import pytest
from sklearn.exceptions import InconsistentVersionWarning

from backend.app.services.phishguard.classifier import PhishguardUnavailable, analyze_email, load_models
from backend.app.services.phishguard.text_preprocessor import clean_text


def test_phishguard_model_artifact_deserialization():
    """Deserialization must not emit an sklearn version-mismatch warning."""
    load_models.cache_clear()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            model, vectorizer = load_models()
        except PhishguardUnavailable as exc:
            pytest.fail(str(exc))
    assert model is not None
    assert vectorizer is not None
    assert not any(issubclass(item.category, InconsistentVersionWarning) for item in caught)

    cleaned = clean_text("URGENT: Your account has been suspended. Click here to verify.")
    matrix = vectorizer.transform([cleaned])
    assert matrix.shape[1] == 5000
    phishing_probability = float(model.predict_proba(matrix)[0][1])
    assert 0.0 <= phishing_probability <= 1.0
    assert phishing_probability > 0.5


def test_preprocessor_preserves_url_and_ip_tokens():
    cleaned = clean_text(
        "Verify at http://192.168.1.50/login.php from 10.1.2.3 before the account is suspended."
    )
    assert "token_url_link" in cleaned or "token_ip_address" in cleaned
    assert "suspended" in cleaned
