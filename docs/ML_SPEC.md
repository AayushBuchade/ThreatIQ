# ThreatIQ — Machine Learning & AI Specification

**Document Version:** 1.0.0  
**Phase:** Phase 0 (Foundation & Architecture)  
**Status:** Approved Baseline  
**ML Governance:** Separation of Training and Inference, Deterministic Evaluation, Explainability Mandatory  

---

## 1. Machine Learning Architectural Principles

ThreatIQ integrates artificial intelligence and machine learning into cybersecurity operations adhering to four fundamental engineering rules:

1. **Strict Separation of Training and Inference:**
   - Inference runs as lightweight, stateless micro-services or asynchronous workers utilizing pre-compiled serialized pipelines (`joblib` / `onnx`).
   - Training runs as an isolated offline or batch-scheduled workflow with dedicated compute, strict seed controls, and stratified cross-validation. Training code is never invoked within real-time request paths.
2. **Deterministic Inputs & Source-Specific Pipelines:**
   - Machine learning models are never applied to arbitrary, unvalidated log formats.
   - Each model accepts a typed, validated schema. Feature extractors convert raw log attributes into numerical/categorical vectors deterministically.
3. **No Black-Box Predictions (Explainability Mandatory):**
   - Every inference output that raises or contributes to a threat score must produce an accompanying human-interpretable explanation (feature attributions, token log-odds, or surrogate rule explanations).
4. **No Fabricated Benchmarks or Synthetic Telemetry:**
   - All performance figures, accuracy claims, and confusion matrices must reflect verifiable datasets and actual test runs recorded in version control.

---

## 2. Model Portfolio & ThreatIQ Module Mapping

| Module | Model Family | Primary Algorithm | Target Task | Input Features | Latency SLA | Target Phase |
|---|---|---|---|---|---|---|
| **Module 2: Anomaly Detection** | Unsupervised Outlier Detection | `IsolationForest` + Robust Scaler | Detect anomalous user logon times, egress volumes, uncommon process spawns | 18 tabular behavioral metrics | < 5 ms | Phase 2 |
| **Module 3: Phishing Protection** | Calibrated Supervised NLP | `LinearSVC` with Platt Sigmoid Calibration (`CalibratedClassifierCV`) | Classify email content and RFC headers as Safe or Phishing | Sublinear TF-IDF (1-2 N-grams, 5000 vocabulary) | < 2 ms | Phase 3 |
| **Module 4: URL Intelligence** | Gradient Boosted Decision Trees | `XGBoost` Classifier | Detect credential harvesting and malicious hosting URLs | 24 lexical, entropy, and structural URL features | < 8 ms | Phase 4 |
| **Module 5: Cyber Risk Prediction** | Supervised Tabular Regression | `RandomForestRegressor` / Ridge | Forecast risk score (0-100) per subnet and cloud asset | Vulnerability density, patch lag, exposure tier | < 15 ms | Phase 6 |
| **Module 6: Vuln Prioritization** | Composite Ranking Model | Weighted EPSS + CVSS v3.1 + Threat Actor Activity | Prioritize remediation queue for SOC teams | Exploit prediction score, asset criticality | < 10 ms | Phase 4 |
| **Module 7: Explainable Threat Analysis** | Local Explainer / Game-Theoretic Attribution | Direct Weight Attribution (Linear) + `LIME` + `SHAP` | Generate token and feature importance for SOC analysts | Model coefficients & neighborhood perturbations | < 5 ms (Linear) / < 3 s (LIME) | Phase 5 |

---

## 3. Detailed Feature Pipelines

### 3.1 Email Threat Feature Pipeline (Inherited from PHISHGUARD)
```
[ Raw Email / .EML ]
         │
         ├──> [ RFC Header Parser ] ────────> Sender Mismatch (From vs Return-Path vs Reply-To)
         │                                   SPF / DKIM / DMARC Status Flag
         │
         ├──> [ Regex IOC Extractor ] ──────> Defanged URLs, High-Risk TLDs (.xyz, .top, .pw)
         │                                   Direct IPv4 Host Counts, Dangerous Attachments
         │
         ├──> [ Cyber Feature Extractor ] ──> Urgency Counts, Credential Keywords, Wire Terms
         │
         └──> [ NLP Preprocessor ] ─────────> Token Masking (<token_url>, <token_ip>)
                                             Stopword Pruning (preserving threat cues)
                                             Sublinear TF-IDF Vector (5,000 Dimensions)
                                                        │
                                                        ▼
                                             [ Calibrated Linear SVM ]
                                                        │
                                                        ▼
                                             Phishing Probability: p ∈ [0.0, 1.0]
```

### 3.2 Security Log Anomaly Pipeline (Module 2)
```
[ Normalized ECS Log Event ]
         │
         ├──> Categorical Encoders (event.action, event.category, process.name)
         ├──> Temporal Cyclic Encoding (hour_sin, hour_cos, day_of_week)
         ├──> Ratio & Count Metrics (failed_logins_last_10m, bytes_out_ratio)
         │
         ▼
[ RobustScaler ]
         │
         ▼
[ IsolationForest (contamination=0.01, n_estimators=200) ]
         │
         ▼
Anomaly Score: s ∈ [-1.0, 1.0] (Converted to Outlier Probability)
```

---

## 4. Threat Risk Scoring Methodology

ThreatIQ computes a composite **Threat Risk Score (0–100)** to unify diverse detection signals into actionable SOC triage categories:

$$\text{ThreatRiskScore} = \min\left(100, \; w_{\text{ML}} \cdot S_{\text{ML}} + w_{\text{Spoof}} \cdot S_{\text{Spoof}} + w_{\text{IOC}} \cdot S_{\text{IOC}} + w_{\text{Heuristic}} \cdot S_{\text{Heuristic}}\right)$$

Where:
- $S_{\text{ML}} \in [0, 40]$: Calibrated statistical machine learning prediction probability ($\text{Prob} \times 40$).
- $S_{\text{Spoof}} \in [0, 20]$: Identity verification failures (SPF/DKIM/DMARC failure or brand display impersonation).
- $S_{\text{IOC}} \in [0, 20]$: High-risk indicators (direct IP host, abusive TLD, executable attachment).
- $S_{\text{Heuristic}} \in [0, 20]$: Coercive urgency cues, credential request terms, and financial wire demands.

### Triage Bands:
- **0 – 34: SAFE / BENIGN** — No alert raised, event cataloged for telemetry baselining.
- **35 – 69: SUSPICIOUS / TIER-1 REVIEW** — Flagged for contextual review, low-priority SOC queue.
- **70 – 100: CRITICAL / IMMEDIATE INCIDENT** — High-priority SOC incident created, real-time alert dispatched to dashboard.

---

## 5. Explainability Architecture (Module 7)

Every inference alert is paired with an explainability payload:

### 5.1 Real-Time Linear Token Attribution
For linear and linear-calibrated classifiers:
$$\text{Contribution}(t) = \text{TF-IDF}(t) \times w_t$$
Active tokens are sorted into:
- **Top Threat Drivers:** Tokens that push the prediction toward malicious.
- **Top Benign Mitigators:** Tokens that indicate legitimate origin.

### 5.2 Deep Surrogate Perturbation (LIME & SHAP)
- For complex decision surfaces (e.g., Random Forest, XGBoost), background workers compute local linear surrogate approximations using `LIME` (text) or `TreeSHAP` (tabular).
- Runs asynchronously to avoid blocking the real-time event pipeline.

---

## 6. Model Governance, Versioning & Serialization

1. **Artifact Location:** Versioned models reside in `backend/app/ml_models/<module>/<version>/`.
2. **Metadata Contract:** Every serialized model file must be accompanied by a `model_metadata.json` specifying:
   - `model_id`: Unique identifier (e.g., `phishguard-linearsvc-v1.0.0`)
   - `sha256_checksum`: Cryptographic hash of the `.joblib` or binary artifact
   - `training_dataset_hash`: Dataset snapshot identifier
   - `training_timestamp`: UTC ISO timestamp
   - `metrics`: Accuracy, Precision, Recall, F1, ROC-AUC, 5-fold CV mean ± std
   - `feature_names`: Explicit feature vector definition
3. **Integrity Validation:** Upon backend startup, the model loader verifies SHA-256 hashes against metadata. Mismatched artifacts trigger a hard failure, preventing corrupted model deployment.
4. **Drift Detection Strategy:**
   - Ingested feature distributions are recorded via running statistical summaries.
   - Population Stability Index (PSI) and Kolmogorov-Smirnov (KS) tests will be evaluated in Phase 2 & 3 against training baselines to detect concept drift.
