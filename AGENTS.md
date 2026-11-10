# ThreatIQ — Agent & Engineering Guidelines

**Document Version:** 1.0.0  
**Phase:** Phase 0 (Foundation & Architecture)  
**Applicability:** All AI Coding Agents & Human Contributors  

---

## 1. Core Engineering & Agent Mandate

When operating in the **ThreatIQ** codebase, agents must function as disciplined Principal Security Software Engineers. Every contribution must produce production-grade, maintainable code rather than ornamental mockups or decorative placeholders.

### Mandatory Rules:
1. **Never Fabricate Data or Results:** Never invent ML benchmark numbers, synthetic telemetry graphs, or fake test results. Always report actual metrics and actual command execution outputs.
2. **Phase Boundary Strictness:** Work only within the active authorized phase. Never jump ahead to future phases (e.g., implementing advanced feature modules) without user review and explicit approval.
3. **Branch Integrity:** Work only on the designated development branch (`dev/foundation` for Phase 0). Never touch `main` or merge branches without explicit user permission.
4. **Security & Zero-Destructive Actions:** ThreatIQ is an intelligence, detection, and decision-support system. Never implement automated or destructive blocking actions (e.g. terminating endpoints, wiping disks, deleting firewall rules) without explicit multi-signature manual controls.
5. **No Secret Commits:** Never hardcode or commit API secrets, credentials, internal IP networks, or private customer logs. Always use `.env` templates and Pydantic Settings.

---

## 2. Documentation Governance & Tracking Policy

ThreatIQ enforces strict synchronization across project tracking documents. After completing or altering any milestone, agents **must update**:

- `README.md` — Public dashboard, tech stack status, and module matrix.
- `PROGRESS.md` — Chronological execution journal detailing commands, tests, and actual results.
- `TASKS.md` — Granular checklist categorized by phase.
- `ROADMAP.md` — High-level phase status, duration estimates, and dependencies.
- `DECISIONS.md` — Architectural Decision Records (ADRs) explaining rationale and trade-offs.

### Permitted Status Labels:
Only four statuses may be assigned to tasks and milestones:
- **Completed** — Fully implemented, passing automated tests, verified end-to-end.
- **In Progress** — Actively being implemented or tested in current session.
- **Upcoming** — Planned for a future phase or blocked behind an earlier milestone.
- **Blocked** — Prevented from progressing due to an identified technical barrier or missing requirement.

> [!CAUTION]
> Never mark an item as **Completed** unless automated tests have been executed and output evidence is logged in `PROGRESS.md`.

---

## 3. Technology Standards

### 3.1 Backend (Python / FastAPI)
- **Framework:** FastAPI with asynchronous endpoint functions (`async def`) for I/O-bound tasks.
- **Data Validation:** Pydantic v2 schemas for all request payloads and response models. Never return unvalidated raw dictionaries.
- **Database Access:** SQLAlchemy 2.0+ declarative models using `Mapped[T]` and `mapped_column()`. Asynchronous sessions via `async_sessionmaker`.
- **Migrations:** Version-controlled Alembic migrations. Never call `metadata.create_all()` in production code.
- **Logging:** Structured JSON logs utilizing contextual correlation IDs (`request_id`). No unstructured `print()` statements in application code.

### 3.2 Frontend (React / Vite / Tailwind)
- **Framework:** React 18+ functional components with Hooks.
- **Styling:** Tailwind CSS with standardized color palette (Navy, Slate, Cyan, Crimson).
- **API Client:** Centralized Axios / Fetch service with baseURL configuration, structured error handling, and toast notifications.
- **State Management:** Clean React state and WebSocket hooks for real-time telemetry streaming.

### 3.3 Machine Learning & Data Pipelines
- **Separation:** Training code resides in offline pipelines; inference runs as stateless services consuming serialized models.
- **Explainability:** Any ML prediction contributing to threat scoring must return interpretable token attributions or feature weights.
- **Integrity:** SHA-256 validation of model weights upon startup.

---

## 4. Testing & Verification Requirements

- **Unit Tests:** Pytest suites covering schema validation, routing, and deterministic logic.
- **Integration Tests:** End-to-end verification of frontend-to-backend-to-database communication.
- **CI Pipeline:** GitHub Actions running linting, type checks, and pytest on all pull requests against `dev/foundation`.

