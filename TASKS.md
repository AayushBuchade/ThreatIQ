# ThreatIQ — Granular Tasks Dashboard

**Document Version:** 1.0.0  
**Tracking Status Policy:** Completed | In Progress | Upcoming | Blocked  
**Active Phase:** Phase 0 (Foundation & Architecture)  

---

## Phase 0: Foundation & Architecture (4–6 Days) — [COMPLETED]

| Task ID | Task Description | Status | Verification Evidence / Artifact |
|:---:|---|:---:|---|
| **T0.1** | Inspect repository, git branch, environment runtimes, and local toolchain | **Completed** | Python 3.13.7, Node v24.20.0, npm 11.19.0, Git 2.52.0 on `dev/foundation` |
| **T0.2** | Audit PHISHGUARD codebase, model artifacts, dependencies, and migration risks | **Completed** | Created `docs/PHISHGUARD_MIGRATION_AUDIT.md` (556L audit, 97.16% SVM, risks cataloged) |
| **T0.3** | Design complete system architecture, modular monolith, and event pipeline | **Completed** | Created `docs/ARCHITECTURE.md` (ECS normalization, Redis Streams, Mermaid diagrams) |
| **T0.4** | Design machine learning governance, feature pipelines, and XAI specifications | **Completed** | Created `docs/ML_SPEC.md` (Offline training vs inference, 0-100 risk score, XAI standards) |
| **T0.5** | Scaffold FastAPI backend with Pydantic v2 schemas and structured JSON logging | **Completed** | Created `backend/app/main.py`, `core/config.py`, `core/logging.py`, `core/security.py` |
| **T0.6** | Configure SQLAlchemy 2.0 ORM models, session management, and Alembic migrations | **Completed** | Initial migration `7a7e248a8277_create_initial_schema.py` applied cleanly |
| **T0.7** | Scaffold React frontend with Vite, Tailwind CSS, Lucide icons, and SOC UI layout | **Completed** | Production bundle built cleanly (`dist/assets/index-*.js`, 1489 modules transformed) |
| **T0.8** | Configure multi-container Docker Compose and `.env.example` templates | **Completed** | Created `docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`, `.env.example` |
| **T0.9** | Implement minimal frontend -> backend -> database integration test | **Completed** | Implemented `/api/v1/events/test-ping` and interactive `TelemetryFeed.jsx` console |
| **T0.10** | Add comprehensive unit/integration test suite with pytest and GitHub Actions CI | **Completed** | Created `backend/tests/` (10 tests) and `.github/workflows/ci.yml` |
| **T0.11** | Execute test suite, verify live database roundtrip, and record actual outputs | **Completed** | **10 passed, 0 failed in 1.46s** (including PhishGuard deserialization baseline) |
| **T0.12** | Author ADR records, roadmap, tasks, execution journal, and agent guidelines | **Completed** | `DECISIONS.md`, `ROADMAP.md`, `TASKS.md`, `PROGRESS.md`, `AGENTS.md`, `README.md` |

---

## Phase 1: Security Ingestion & Monitoring (8–12 Days) — [UPCOMING]

| Task ID | Task Description | Target Module | Status |
|:---:|---|:---:|:---:|
| **T1.1** | Implement asynchronous Syslog (RFC 5424 / RFC 3164) listener over UDP/TCP | Module 1 | **Upcoming** |
| **T1.2** | Build CEF (Common Event Format) parser and ECS normalization engine | Module 1 | **Upcoming** |
| **T1.3** | Implement Redis Streams producer and consumer group workers | Module 1 | **Upcoming** |
| **T1.4** | Configure WebSockets endpoint (`/ws/telemetry`) for streaming live events to UI | Module 1 | **Upcoming** |
| **T1.5** | Implement rate limiting and backpressure protection on ingestion endpoints | Module 1 | **Upcoming** |
| **T1.6** | Build React live telemetry event stream viewer with filter controls | Module 1 | **Upcoming** |

---

## Phase 2: AI Anomaly Detection (10–15 Days) — [UPCOMING]

| Task ID | Task Description | Target Module | Status |
|:---:|---|:---:|:---:|
| **T2.1** | Build offline training pipeline for `IsolationForest` on tabular security events | Module 2 | **Upcoming** |
| **T2.2** | Implement tabular feature extractor (cyclical timestamps, velocity metrics) | Module 2 | **Upcoming** |
| **T2.3** | Implement real-time streaming anomaly inference service | Module 2 | **Upcoming** |
| **T2.4** | Build model drift monitoring with Kolmogorov-Smirnov statistical tests | Module 2 | **Upcoming** |
| **T2.5** | Build React anomaly radar and outlier score visualization widget | Module 2 | **Upcoming** |

---

## Phase 3: PHISHGUARD & Email Protection (10–14 Days) — [UPCOMING]

| Task ID | Task Description | Target Module | Status |
|:---:|---|:---:|:---:|
| **T3.1** | Port PHISHGUARD `security_analyzer.py` and `text_preprocessor.py` into backend | Module 3 | **Upcoming** |
| **T3.2** | Ingest serialized Calibrated Linear SVM and TF-IDF vectorizer with SHA-256 checks | Module 3 | **Upcoming** |
| **T3.3** | Implement `/api/v1/email/analyze` and `/api/v1/email/parse-eml` endpoints | Module 3 | **Upcoming** |
| **T3.4** | Build Gmail & Microsoft Graph webhook ingestion forwarders | Module 3 | **Upcoming** |
| **T3.5** | Build React email threat forensic inspector (headers, defanged URLs, XAI tags) | Module 3 | **Upcoming** |

---

## Phase 4: URL & Vulnerability Intelligence (10–14 Days) — [UPCOMING]

| Task ID | Task Description | Target Module | Status |
|:---:|---|:---:|:---:|
| **T4.1** | Train and serialize XGBoost URL classification model on lexical features | Module 4 | **Upcoming** |
| **T4.2** | Build passive URL extraction, defanging, and high-risk TLD intelligence engine | Module 4 | **Upcoming** |
| **T4.3** | Integrate EPSS (Exploit Prediction Scoring System) and CVSS v3.1 feed ingestion | Module 6 | **Upcoming** |
| **T4.4** | Build vulnerability prioritization queue and remediation ranking service | Module 6 | **Upcoming** |
| **T4.5** | Build React URL threat lookup and vulnerability backlog dashboard | Modules 4, 6 | **Upcoming** |

---

## Phase 5: SOC Incidents & Explainable AI (12–16 Days) — [UPCOMING]

| Task ID | Task Description | Target Module | Status |
|:---:|---|:---:|:---:|
| **T5.1** | Create SOC incident case management models, triage states, and assignment logic | Module 8 | **Upcoming** |
| **T5.2** | Implement dual-mode explainability: instant linear weights + async LIME worker | Module 7 | **Upcoming** |
| **T5.3** | Build automated SOC forensic PDF report generator | Module 8 | **Upcoming** |
| **T5.4** | Build React SOC Case Management Kanban board and triage workflow | Modules 7, 8 | **Upcoming** |

---

## Phase 6: Risk Intelligence & Attack Paths (14–20 Days) — [UPCOMING]

| Task ID | Task Description | Target Module | Status |
|:---:|---|:---:|:---:|
| **T6.1** | Implement quantitative asset cyber risk prediction model (0–100 scale) | Module 5 | **Upcoming** |
| **T6.2** | Build MITRE ATT&CK attack path graph correlation engine | Module 10 | **Upcoming** |
| **T6.3** | Build interactive React attack path graph canvas (lateral movement visualization) | Module 10 | **Upcoming** |

---

## Phase 7: AI Copilot, Simulation & Release (15–22 Days) — [UPCOMING]

| Task ID | Task Description | Target Module | Status |
|:---:|---|:---:|:---:|
| **T7.1** | Build AI Security Copilot natural language triage assistant | Module 9 | **Upcoming** |
| **T7.2** | Implement security assumption validation probe runner (strictly non-destructive) | Module 11 | **Upcoming** |
| **T7.3** | Build Monte Carlo risk investment ROI simulation engine | Module 12 | **Upcoming** |
| **T7.4** | Conduct end-to-end security penetration testing, load testing, and v1.0.0 release | All | **Upcoming** |

