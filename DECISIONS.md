# ThreatIQ — Architecture Decision Records (ADR)

**Document Version:** 1.0.0  
**Phase:** Phase 0 (Foundation & Architecture)  
**Status:** Approved  

---

## Index of Architecture Decision Records

- [ADR-001: Modular Monolith Architecture Pattern](#adr-001-modular-monolith-architecture-pattern)
- [ADR-002: Core Technology Stack Rationale](#adr-002-core-technology-stack-rationale)
- [ADR-003: PHISHGUARD Migration & Integration Strategy](#adr-003-phishguard-migration--integration-strategy)
- [ADR-004: Decoupling ML Training from Streaming Inference](#adr-004-decoupling-ml-training-from-streaming-inference)
- [ADR-005: Strict Non-Destructive Security Guarantee](#adr-005-strict-non-destructive-security-guarantee)
- [ADR-006: Dual Database Driver Support (PostgreSQL / SQLite)](#adr-006-dual-database-driver-support-postgresql--sqlite)

---

### ADR-001: Modular Monolith Architecture Pattern

#### Context
ThreatIQ encompasses 12 interconnected cybersecurity and SOC intelligence modules. A common pitfall in modern security platform engineering is decomposing into distributed microservices prematurely, incurring significant network latency, distributed transaction complexity, RPC failure modes, and CI/CD overhead.

#### Decision
We adopt a **Modular Monolith** architecture for ThreatIQ. Domain components communicate via internal typed interfaces and an asynchronous Redis Streams event bus. Services are structured with strict boundaries within a single codebase.

#### Consequences
- **Positive:** Simplified local development, instantaneous in-process function invocation, zero distributed serialization tax, atomic migrations via Alembic.
- **Negative:** Shared process memory requires strict module boundary discipline to prevent leaky abstractions.
- **Future Evolution:** If a specific workload (e.g. heavy LIME XAI or PCAP parsing) requires independent elastic horizontal scaling, it can be extracted cleanly into an independent container service consuming from the Redis Stream.

---

### ADR-002: Core Technology Stack Rationale

#### Context
The platform requires high-speed asynchronous log ingestion, strict data schema validation, relational persistence, real-time SOC analyst dashboards, and integration with scientific Python ML ecosystems.

#### Decision
- **Backend:** Python 3.13, FastAPI (ASGI async core), Pydantic v2 (C-extension typed schema validation).
- **Persistence:** PostgreSQL 16 with SQLAlchemy 2.0 (declarative mapped columns) and Alembic migrations.
- **Streaming & Cache:** Redis 7 Streams (consumer groups with offset tracking).
- **Frontend:** React 18, Vite 5, Tailwind CSS (fast HMR, dark cyber SOC UI tokens).
- **ML & XAI:** Scikit-learn, XGBoost, Isolation Forest, LIME, SHAP.

#### Consequences
- Optimal balance of developer velocity, execution performance, typed safety, and machine learning compatibility.

---

### ADR-003: PHISHGUARD Migration & Integration Strategy

#### Context
The upstream PHISHGUARD project contains a validated, pre-trained ML model (97.16% accuracy Calibrated Linear SVM on 18,650 verified emails), RFC 822/2822 email parsing, IOC extraction, and LIME explainability. The upstream repository must remain unmodified.

#### Decision
We conducted a comprehensive audit (`docs/PHISHGUARD_MIGRATION_AUDIT.md`) and designed an adapter pattern for Phase 3:
1. Preserve upstream PHISHGUARD intact.
2. Ingest pre-trained `best_model.joblib` and `tfidf_vectorizer.joblib` with cryptographic SHA-256 validation.
3. Decouple the monolithic Streamlit UI into headless FastAPI endpoints and React dashboard views.
4. Separate instantaneous linear token attribution (< 5ms) for real-time triage from heavy LIME perturbations offloaded to background workers.

#### Consequences
- Eliminates redundant model training; provides an immediate enterprise-grade phishing detection capability.

---

### ADR-004: Decoupling ML Training from Streaming Inference

#### Context
Applying machine learning directly within API request loops can lead to severe latency spikes, memory bloat, and non-deterministic behavior during log ingestion spikes.

#### Decision
- **Inference Mode:** Runs as lightweight, stateless services consuming pre-compiled, versioned model binaries (`.joblib` / `.onnx`) using frozen schemas.
- **Training Mode:** Runs as offline batch jobs or scheduled Airflow/Prefect pipelines on dedicated compute, storing artifacts with metadata manifests.
- Models are strictly source-specific: no arbitrary model is applied to incompatible telemetry streams.

#### Consequences
- Inference achieves sub-10ms response times without memory pressure or training interference.

---

### ADR-005: Strict Non-Destructive Security Guarantee

#### Context
Automated cybersecurity tools that execute unverified blocking actions (e.g. killing system processes, dropping production firewall rules, or terminating cloud instances) present catastrophic operational risks to organizations.

#### Decision
ThreatIQ enforces an architectural policy: **Zero Automated Destructive Actions**.
- The platform functions strictly as an intelligence, detection, and decision-support engine.
- Remediation actions generate structured playbooks and require explicit, multi-party manual authorization before execution.
- Configured via `ALLOW_DESTRUCTIVE_ACTIONS=false` and enforced at the middleware/service boundary.

#### Consequences
- Eliminates catastrophic self-inflicted denial-of-service events; builds SOC analyst trust.

---

### ADR-006: Dual Database Driver Support (PostgreSQL / SQLite)

#### Context
Production and containerized deployments utilize PostgreSQL 16 with connection pooling. However, local developer onboarding and CI test pipelines benefit from zero-dependency in-memory execution. Furthermore, Windows sandbox environments restrict socket/pipe IPC between threads.

#### Decision
Using SQLAlchemy 2.0 abstractions, ThreatIQ natively supports:
1. **Production:** `postgresql+psycopg://` / `postgresql+asyncpg://` connecting to PostgreSQL 16.
2. **Local Dev & Testing:** `sqlite:///./threatiq.db` and in-memory SQLite (`sqlite:///:memory:`) with `StaticPool`.
3. Deterministic Alembic migrations compatible across dialect layers.

#### Consequences
- Complete developer flexibility, instant CI test execution, and seamless production readiness.

