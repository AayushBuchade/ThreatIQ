"""
ThreatIQ System Service
Maintains platform status, module catalogs, and service health evaluations.
"""

import time
from typing import List, Dict, Any
from backend.app.core.config import settings
from backend.app.schemas.system import ModuleStatus

# Server start timestamp for uptime calculation
START_TIME = time.time()

# 12 Target Platform Modules Definition and Current Lifecycle Status
PLATFORM_MODULES: List[Dict[str, Any]] = [
    {
        "id": 1,
        "name": "Real-Time Security Log Monitoring",
        "target_phase": 1,
        "status": "Upcoming",
        "tech_scope": "Syslog / CEF / ECS Ingestion",
        "description": "Multi-source streaming telemetry ingestion, parsing, and real-time event indexing."
    },
    {
        "id": 2,
        "name": "AI Anomaly Detection",
        "target_phase": 2,
        "status": "Upcoming",
        "tech_scope": "Isolation Forest / Behavioral Scalers",
        "description": "Unsupervised baseline deviation detection for user logon and network volumetric anomalies."
    },
    {
        "id": 3,
        "name": "Live Gmail/Outlook Phishing Protection",
        "target_phase": 3,
        "status": "Upcoming",
        "tech_scope": "Calibrated Linear SVM / RFC 822",
        "description": "Ported PHISHGUARD engine analyzing headers, spoofing cues, and token-level NLP."
    },
    {
        "id": 4,
        "name": "Malicious URL Intelligence",
        "target_phase": 4,
        "status": "Upcoming",
        "tech_scope": "XGBoost / Lexical Feature Extractor",
        "description": "Passive URL defanging, credential phishing detection, and high-risk TLD analysis."
    },
    {
        "id": 5,
        "name": "Cyber Risk Prediction & Monitoring",
        "target_phase": 6,
        "status": "Upcoming",
        "tech_scope": "Composite Scoring / Time-Series Regressor",
        "description": "Continuous asset posture tracking, breach likelihood estimation, and trend forecasting."
    },
    {
        "id": 6,
        "name": "Vulnerability Prioritization",
        "target_phase": 4,
        "status": "Upcoming",
        "tech_scope": "EPSS / CVSS v3.1 / Threat Intelligence",
        "description": "Exploit-prediction-weighted patch triage queue ordering vulnerabilities by exploitability."
    },
    {
        "id": 7,
        "name": "Explainable Threat Analysis",
        "target_phase": 5,
        "status": "Upcoming",
        "tech_scope": "XAI / Token Weights / LIME / SHAP",
        "description": "Human-interpretable attributions and decision justifications for SOC analysts."
    },
    {
        "id": 8,
        "name": "SOC Incident Management",
        "target_phase": 5,
        "status": "Upcoming",
        "tech_scope": "Case Workflow / PDF Forensic Reports",
        "description": "Incident lifecycle tracking, triage states, analyst assignment, and formal audit exports."
    },
    {
        "id": 9,
        "name": "AI Security Copilot",
        "target_phase": 7,
        "status": "Upcoming",
        "tech_scope": "LLM Assistant / Triage Playbooks",
        "description": "Context-aware conversational assistance guiding tier-1 and tier-2 incident triage."
    },
    {
        "id": 10,
        "name": "Attack Path Visualization",
        "target_phase": 6,
        "status": "Upcoming",
        "tech_scope": "Graph Networks / MITRE ATT&CK",
        "description": "Visual kill-chain topology highlighting lateral movement risks across enterprise assets."
    },
    {
        "id": 11,
        "name": "Security Assumption Validation",
        "target_phase": 7,
        "status": "Upcoming",
        "tech_scope": "Posture Verification / Non-destructive Probes",
        "description": "Continuous validation that defense controls and configurations hold against assumptions."
    },
    {
        "id": 12,
        "name": "Risk Investment Simulation",
        "target_phase": 7,
        "status": "Upcoming",
        "tech_scope": "Monte Carlo / Cyber Risk Economics",
        "description": "Cost-benefit and loss-reduction simulations for security budget allocations."
    }
]


def get_uptime_seconds() -> float:
    """Returns uptime of current server process in seconds."""
    return round(time.time() - START_TIME, 2)


def get_platform_modules() -> List[ModuleStatus]:
    """Returns catalog of all 12 platform modules."""
    return [ModuleStatus(**m) for m in PLATFORM_MODULES]

