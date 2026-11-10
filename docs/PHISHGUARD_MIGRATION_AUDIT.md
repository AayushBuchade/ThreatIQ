# ThreatIQ — PHISHGUARD Migration Audit

**Document Version:** 1.0.0  
**Audit Date:** 2026-11-10  
**Auditor:** ThreatIQ Lead Systems & Security Architecture  
**Source Repository:** [AayushBuchade/PHISHGUARD](https://github.com/AayushBuchade/PHISHGUARD)  
**Target Repository:** [AayushBuchade/ThreatIQ](https://github.com/AayushBuchade/ThreatIQ)  
**Target Branch:** `dev/foundation`  
**Planned Integration Phase:** Phase 3 (PHISHGUARD & Email Protection)

---

## 1. Executive Summary

ThreatIQ incorporates email security, credential harvesting detection, and forensic triage as one of its core pillars (Module 3: Live Gmail/Outlook Phishing Protection, Module 4: Malicious URL Intelligence, Module 7: Explainable Threat Analysis). 

Rather than developing email forensics and phishing NLP classification from scratch, the pre-existing **PHISHGUARD** project provides a battle-tested, high-accuracy baseline trained on **18,650 verified real-world emails**. The primary objective of this audit is to systematically evaluate PHISHGUARD's codebase, model artifacts, dependencies, performance characteristics, and architectural seams, establishing a zero-regression migration roadmap into ThreatIQ's modular monolith.

### Key Audit Findings:
1. **Proven ML Baseline:** The Calibrated Linear Support Vector Machine (`LinearSVC` with Platt scaling) achieves **97.16% holdout accuracy**, **96.42% F1-score**, and **0.9957 ROC-AUC** with sub-2ms inference latency.
2. **Deterministic Forensics:** High-fidelity RFC 822/2822 parsing, defensive defanging, brand impersonation detection, and RFC-compliant SPF/DKIM/DMARC status analysis operate without third-party network egress or cloud dependencies.
3. **Decoupling Needed:** PHISHGUARD was originally structured as a monolithic Streamlit application with synchronous CLI test execution. To integrate into ThreatIQ, its components must be adapted into headless asynchronous services, Redis-backed event processors, PostgreSQL persistent schemas, and React UI components.

---

## 2. Source Code & Component Inventory

| File Path | Lines | Primary Responsibility | Dependencies | Reusability Grade | Target ThreatIQ Module |
|---|---|---|---|---|---|
| `src/security_analyzer.py` | 556 | RFC 822/2822 parsing, IOC extraction, brand spoofing detection, authentication parsing, 0-100 Threat Risk Scoring | `email`, `re`, `urllib.parse` | **A (Direct Reuse with Typed Schemas)** | Module 3, Module 4, Module 8 |
| `src/text_preprocessor.py` | 136 | Cyber-aware NLP cleaning, token preservation (`<token_url_link>`, `<token_ip_address>`), custom stopword filtering | `re`, `html`, `string` | **A (Direct Reuse)** | Module 3, Module 7 |
| `src/feature_engineering.py` | 146 | Urgency cues, credential harvesting keywords, financial wire cues, brand regex metrics | `re`, `numpy`, `pandas` | **A (Direct Reuse)** | Module 3, Module 5 |
| `src/explainability.py` | 163 | Instantaneous linear weight token attribution and LIME local surrogate explanations | `joblib`, `numpy`, `lime`, `scikit-learn` | **B+ (Needs Async Offloading for LIME)** | Module 7 |
| `src/model_trainer.py` | 240 | 5-Fold Stratified CV, training pipeline for LinearSVM, LogReg, NaiveBayes, RandomForest | `scikit-learn`, `joblib`, `pandas` | **B (Offline Training Pipeline)** | ML Offline Pipeline |
| `src/report_generator.py` | 290 | SOC forensic investigation PDF report generation | `fpdf`, `time` | **B (Adapter for ThreatIQ Layout)** | Module 8 |
| `src/data_loader.py` | 85 | Dataset loading and splitting from raw CSV/JSON | `pandas`, `sklearn` | **B (Offline Utility)** | ML Offline Pipeline |
| `app.py` | 420 | Streamlit interactive UI | `streamlit` | **C (Decommission in favor of React/FastAPI)** | Replaced by React UI |
| `tests/test_e2e.py` | 106 | 6-stage end-to-end unit and inference verification | `pytest`, `joblib` | **A (Port to pytest in ThreatIQ backend)** | Backend Test Suite |

---

## 3. Model Artifacts & Evaluation Audit

### 3.1 Model Artifact Files
The `models/` directory in PHISHGUARD contains verified serialized assets:
- `best_model.joblib` (122 KB): Serialized `CalibratedClassifierCV(estimator=LinearSVC(C=1.0, max_iter=2000), method='sigmoid', cv=5)`.
- `tfidf_vectorizer.joblib` (188 KB): Serialized `TfidfVectorizer(max_features=5000, ngram_range=(1,2), sublinear_tf=True)`.
- `all_models.joblib` (8.4 MB): Ensemble dictionary containing all 4 benchmarked models (`Linear SVM (Calibrated)`, `Logistic Regression`, `Random Forest`, `Multinomial Naive Bayes`).
- `model_metadata.json` (988 bytes): Verified training run parameters and confusion matrix metrics.
- `model_comparison.json` (2.3 KB): Detailed 5-fold cross-validation metrics across all evaluated classifiers.

### 3.2 Performance Verification
| Classifier | Holdout Accuracy | Precision | Recall | F1-Score | ROC-AUC | Mean CV F1 | Inference Latency |
|---|---|---|---|---|---|---|---|
| **Calibrated Linear SVM** | **97.16%** | **95.14%** | **97.74%** | **96.42%** | **0.9957** | **96.32% ± 0.33%** | **< 2 ms** |
| Logistic Regression | 96.65% | 94.84% | 96.72% | 95.77% | 0.9950 | 95.79% ± 0.33% | < 2 ms |
| Random Forest | 95.41% | 93.88% | 94.46% | 94.17% | 0.9902 | 93.85% ± 0.28% | ~ 28 ms |
| Multinomial Naive Bayes | 94.98% | 93.46% | 93.78% | 93.62% | 0.9889 | 94.13% ± 0.37% | < 1 ms |

### 3.3 Holdout Confusion Matrix (Evaluated on 3,727 Unseen Emails)
- **True Negatives (Legitimate Cleared):** 2,192
- **False Positives (Legitimate Flagged):** 73 (3.2% False Positive Rate)
- **False Negatives (Phishing Missed):** 33 (**2.2% False Negative Rate**)
- **True Positives (Phishing Caught):** 1,429

---

## 4. Reusable Capabilities & Feature Mapping

```
+-------------------------------------------------------------+
|                     PHISHGUARD ASSETS                       |
+-------------------------------------------------------------+
          |                      |                   |
          v                      v                   v
+------------------+   +-------------------+   +--------------------+
| Email Forensics  |   | ML Classification |   | Explainability &   |
| & IOC Extraction |   | & Risk Scoring    |   | Incident Reporting |
+------------------+   +-------------------+   +--------------------+
          |                      |                   |
          |                      |                   |
          v                      v                   v
+-------------------------------------------------------------+
|                      THREATIQ MODULES                       |
|                                                             |
| [Module 3: Phishing Protection]                             |
|  - Ingest Gmail/Outlook via Webhooks & IMAP                 |
|  - Execute SecurityAnalyzer.parse_eml_content()             |
|  - Execute Linear SVM inference on TF-IDF representation    |
|                                                             |
| [Module 4: URL Intelligence]                                |
|  - Consume defanged URLs & IPs from extract_iocs()          |
|  - Correlate with domain reputation & threat feeds          |
|                                                             |
| [Module 7: Explainable Threat Analysis]                     |
|  - Instantaneous token log-odds attribution                 |
|  - Async LIME background jobs for deep forensic cases       |
|                                                             |
| [Module 8: SOC Incident Management]                         |
|  - Generate Forensic Incident Tickets in PostgreSQL        |
|  - Export PDF investigation audit reports                   |
+-------------------------------------------------------------+
```

---

## 5. Migration Risks, Challenges & Gaps

### 5.1 Architectural Gaps
1. **Monolithic UI Coupling:** PHISHGUARD utilizes Streamlit for rendering. ThreatIQ requires a headless API (`/api/v1/email-threats/*`) with Pydantic request/response schemas and a React/Tailwind frontend.
2. **Synchronous Execution Bottleneck:** LIME explanation computation requires 1,000–5,000 text perturbations and takes between 1.5 and 4.0 seconds per email. Executing this synchronously in an HTTP request would block FastAPI event loops.
   *Mitigation:* Use instantaneous linear weight attribution for real-time triage responses (< 5ms), and offload deep LIME runs to Redis Streams background workers.
3. **Storage & Audit Persistence:** PHISHGUARD retains no state across restarts. ThreatIQ requires persistent storage of parsed incidents, extracted IOCs, sender mismatch flags, and triage outcomes in PostgreSQL via SQLAlchemy models.

### 5.2 Dependency & Environment Compatibility
1. **Scikit-learn Serialization:** Python `joblib` artifacts can produce compatibility warnings or unpickling failures if the scikit-learn minor version differs between training and inference environments.
   *Mitigation:* Pin scikit-learn to compatible release (`>=1.4.0`) and provide a verification test in CI that validates artifact deserialization and test vector prediction accuracy.
2. **PDF Generation (FPDF):** PHISHGUARD uses `fpdf` 1.7.2 which requires manual character sanitization to Latin-1.
   *Mitigation:* Wrap PDF generation in an isolated reporting service and evaluate `fpdf2` (Unicode UTF-8 native) during Phase 3 migration.
3. **Safety & Security Constraints:** PHISHGUARD is strictly passive and does not make network requests to extracted URLs or execute attachments. This defensive design must be strictly preserved in ThreatIQ.

---

## 6. Phased Migration Execution Plan (Phase 3 Roadmap)

| Milestone | Task Description | Verification Criteria |
|---|---|---|
| **M3.1: Core Library Port** | Port `text_preprocessor.py`, `feature_engineering.py`, and `security_analyzer.py` into `backend/app/services/phishguard/` | 100% unit test pass matching PHISHGUARD `test_e2e.py` outputs |
| **M3.2: Artifact Ingestion** | Import `best_model.joblib` and `tfidf_vectorizer.joblib` into `backend/app/ml_models/phishing/` with checksum validation | Deserialization succeeds and model outputs exact probability on test vectors |
| **M3.3: API & Schemas** | Implement `/api/v1/email/analyze`, `/api/v1/email/parse-eml`, and `/api/v1/email/explain` endpoints with Pydantic models | Typed OpenAPI documentation available and integration tests pass |
| **M3.4: Database Schema** | Create `EmailIncident`, `ExtractedIOC`, and `EmailSenderAudit` tables with Alembic migrations | Migrations apply cleanly and relations query with sub-10ms indices |
| **M3.5: Async Worker** | Implement Redis Streams consumer for heavy LIME XAI tasks and async PDF report generation | Background task completes and notifies frontend via WebSocket |
| **M3.6: React Dashboard** | Build React UI for email threat triage: header inspector, IOC viewer, XAI token highlights, and PDF export | Interactive user verification and responsive layout |

---

## 7. Audit Sign-off

- **Audit Status:** COMPLETED
- **Target Integration Phase:** Phase 3 (PHISHGUARD & Email Protection)
- **Actionable Verdict:** Ready for modular migration without modifications to the upstream PHISHGUARD repository.

