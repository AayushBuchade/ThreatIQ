# ThreatIQ — Strategic Development Roadmap

**Document Version:** 1.0.0  
**Active Phase:** Phase 0 (Foundation & Architecture)  
**Total Estimated Effort:** 83–119 development days  
**Target Repository Branch:** `dev/foundation`  

---

## 1. Eight-Phase Platform Roadmap Overview

| Phase | Scope Description | Target Modules | Estimated Duration | Status |
|:---:|---|:---:|:---:|:---:|
| **0** | **Foundation & Architecture** | Platform Baseline | 4–6 days | **Completed** |
| **1** | **Security Ingestion & Monitoring** | Module 1 | 8–12 days | **Upcoming** |
| **2** | **AI Anomaly Detection** | Module 2 | 10–15 days | **Upcoming** |
| **3** | **PHISHGUARD & Email Protection** | Module 3 | 10–14 days | **Upcoming** |
| **4** | **URL & Vulnerability Intelligence** | Modules 4 & 6 | 10–14 days | **Upcoming** |
| **5** | **SOC Incidents & Explainable AI** | Modules 7 & 8 | 12–16 days | **Upcoming** |
| **6** | **Risk Intelligence & Attack Paths** | Modules 5 & 10 | 14–20 days | **Upcoming** |
| **7** | **AI Copilot, Simulation & Release** | Modules 9, 11 & 12 | 15–22 days | **Upcoming** |

> [!IMPORTANT]
> These durations represent development effort days, not elapsed calendar time. Phase boundaries are strictly gated: progression to subsequent phases requires formal architecture review and explicit authorization.

---

## 2. Granular Phase Breakdown

```
+---------------------------------------------------------------------------------------------------------+
|                                      THREATIQ RELEASE PHASES                                            |
+---------------------------------------------------------------------------------------------------------+
  Phase 0: Foundation & Core Scaffolding              [COMPLETED - Verified Baseline]
    │
    ▼
  Phase 1: Multi-Source Security Ingestion            [Syslog, CEF, ECS, Redis Streams Bus]
    │
    ▼
  Phase 2: AI Behavioral Anomaly Detection           [Isolation Forest, Robust Scaling, Deviations]
    │
    ▼
  Phase 3: PHISHGUARD & Live Email Protection        [Linear SVM Port, RFC 822 Forensics, Webhooks]
    │
    ▼
  Phase 4: Malicious URL & Vuln Prioritization       [XGBoost Classifier, EPSS / CVSS Scoring]
    │
    ▼
  Phase 5: SOC Incidents & Explainable XAI           [Case Management, Token Attribution, LIME, PDFs]
    │
    ▼
  Phase 6: Risk Intelligence & Attack Paths          [Asset Risk Scoring, MITRE ATT&CK Graph Topology]
    │
    ▼
  Phase 7: AI Copilot, Assumption Testing & Release   [Conversational Copilot, Monte Carlo, Production]
```

### Phase 0: Foundation & Architecture (4–6 days) — [COMPLETED]
- **Deliverables:**
  - Audited local environment, Python 3.13, Node 24, Docker Compose.
  - Comprehensive source code and model audit of PHISHGUARD (`docs/PHISHGUARD_MIGRATION_AUDIT.md`).
  - System architecture and streaming pipeline design (`docs/ARCHITECTURE.md`).
  - Machine learning and governance specification (`docs/ML_SPEC.md`).
  - Scaffolding of FastAPI backend (SQLAlchemy 2.0, Pydantic v2, Alembic migrations).
  - Scaffolding of React frontend (Vite, Tailwind CSS, SOC Dashboard UI).
  - Verified full-stack integration: UI -> API -> Database roundtrip latency (< 5ms).
  - 10 passing unit and integration tests with pytest.
  - Multi-stage Docker Compose orchestration & GitHub Actions CI quality gate.

### Phase 1: Security Ingestion & Monitoring (8–12 days) — [UPCOMING]
- **Target:** Module 1 (Real-Time Security Log Monitoring)
- **Key Deliverables:**
  - Syslog (RFC 5424 / RFC 3164) listener over UDP/TCP.
  - Common Event Format (CEF) and Elastic Common Schema (ECS) standardizers.
  - Redis Streams ingestion bus (`threatiq:events:raw`, `threatiq:events:normalized`).
  - Real-time WebSocket event dispatch to React telemetry viewer.
  - Ingestion rate limiter and defensive backpressure controls.

### Phase 2: AI Anomaly Detection (10–15 days) — [UPCOMING]
- **Target:** Module 2 (AI Anomaly Detection)
- **Key Deliverables:**
  - Unsupervised `IsolationForest` pipeline for tabular security logs.
  - Feature extraction: temporal cyclical metrics, login failure velocity, egress ratios.
  - Outlier scoring and automatic anomaly thresholding.
  - Model serialization manifest and drift monitoring.

### Phase 3: PHISHGUARD & Email Protection (10–14 days) — [UPCOMING]
- **Target:** Module 3 (Live Gmail/Outlook Phishing Protection)
- **Key Deliverables:**
  - Ingest PHISHGUARD RFC 822 parser, NLP token preprocessor, and feature engineering.
  - Load pre-trained Calibrated Linear SVM (97.16% holdout accuracy) with SHA-256 validation.
  - Implement `/api/v1/email/analyze` and `/api/v1/email/parse-eml` endpoints.
  - Gmail and Microsoft Graph webhook ingestion adapters.
  - Instantaneous token attribution (< 2ms) and React email triage inspector.

### Phase 4: URL & Vulnerability Intelligence (10–14 days) — [UPCOMING]
- **Target:** Module 4 (Malicious URL Intelligence) & Module 6 (Vulnerability Prioritization)
- **Key Deliverables:**
  - XGBoost URL lexical feature classification pipeline.
  - Passive defanging, domain reputation, and high-risk TLD analysis.
  - Exploit Prediction Scoring System (EPSS) and CVSS v3.1 prioritization queue.
  - Asset vulnerability linkage in PostgreSQL.

### Phase 5: SOC Incidents & Explainable AI (12–16 days) — [UPCOMING]
- **Target:** Module 7 (Explainable Threat Analysis) & Module 8 (SOC Incident Management)
- **Key Deliverables:**
  - Full SOC incident management: Case ticketing, triage states (New, Investigating, Remediated, Closed).
  - Dual-mode explainability: Direct linear token weights + Async background LIME worker.
  - SOC investigation PDF forensic report generator (FPDF/ReportLab).
  - Real-time incident alert notifications over WebSockets.

### Phase 6: Risk Intelligence & Attack Paths (14–20 days) — [UPCOMING]
- **Target:** Module 5 (Cyber Risk Prediction) & Module 10 (Attack Path Visualization)
- **Key Deliverables:**
  - Asset risk scoring model (0–100 scale across subnets, identities, and endpoints).
  - Graph-based attack path modeling using MITRE ATT&CK framework.
  - Interactive React topology canvas highlighting lateral movement paths.

### Phase 7: AI Copilot, Investment Simulation & Release (15–22 days) — [UPCOMING]
- **Target:** Module 9 (AI Copilot), Module 11 (Security Assumption Testing), Module 12 (Investment Simulation)
- **Key Deliverables:**
  - Conversational AI Copilot assisting analysts with playbook execution.
  - Posture validation testing against security baseline assumptions.
  - Monte Carlo cyber risk investment ROI simulation engine.
  - End-to-end security penetration audit, load testing, and v1.0.0 release.

---

## 3. Phase-Gate Acceptance Criteria

Before transitioning from any phase to the next, the following gate criteria must be satisfied:
1. **100% Automated Test Pass Rate:** All unit, integration, and contract tests pass.
2. **Zero Fabricated Results:** All recorded accuracy metrics and telemetry reflect actual runs.
3. **No Unhandled Migrations:** Alembic schema migrations apply and rollback cleanly.
4. **Documentation Synchronization:** All 5 core tracking files updated to identical states.
5. **Formal Approval:** Explicit stakeholder sign-off prior to opening next branch.

