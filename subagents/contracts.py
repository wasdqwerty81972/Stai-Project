"""
subagents/contracts.py — Unified Subagent Contracts for SVS-Cyber

Provides typed definitions for:
- Core autonomous profiles (general, security_task, security_validation)
- SVS-Cyber defensive specialist profiles (threat_analysis, malware_analysis, incident_investigation, etc.)
- Structured verdicts (confirmed, rejected, inconclusive, completed, failed)
- Validation confidence levels (high, medium, low, unconfirmed)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class SubagentProfile(str, Enum):
    # Core autonomous worker profiles
    GENERAL = "general"
    SECURITY_TASK = "security_task"
    SECURITY_VALIDATION = "security_validation"

    # SVS-Cyber defensive specialist profiles
    THREAT_ANALYSIS = "threat_analysis"
    MALWARE_ANALYSIS = "malware_analysis"
    INCIDENT_INVESTIGATION = "incident_investigation"
    LOG_ANALYSIS = "log_analysis"
    NETWORK_DEFENSE = "network_defense"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    DETECTION_ENGINEERING = "detection_engineering"
    FORENSICS_INVESTIGATION = "forensics_investigation"
    REMEDIATION_PLANNING = "remediation_planning"
    SECURITY_RESEARCH = "security_research"


class SubagentVerdict(str, Enum):
    """Structured verdict from subagent investigation."""
    CONFIRMED = "confirmed"          # Hypothesis or vulnerability verified with evidence
    REJECTED = "rejected"            # Hypothesis refuted or vulnerability candidate falsified
    INCONCLUSIVE = "inconclusive"    # Insufficient telemetry to confirm or reject
    COMPLETED = "completed"          # Task executed successfully (general tasks)
    FAILED = "failed"                # Subagent execution failed or timed out


class ValidationConfidence(str, Enum):
    """Confidence level assigned to findings by independent validation subagents."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNCONFIRMED = "unconfirmed"


class SubagentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SETTLED = "settled"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    FAILED = "failed"


class SubagentCapabilityBundle(str, Enum):
    """Scoped tool bundles assigned to subagents."""
    CODE_READ = "code_read"
    CODE_WRITE = "code_write"
    TERMINAL = "terminal"
    WEB_RESEARCH = "web_research"
    BROWSER_QA = "browser_qa"
    NETWORK_DIAGNOSTICS = "network_diagnostics"
    MALWARE_TRIAGE = "malware_triage"
    LOG_ANALYSIS = "log_analysis"
    SYSTEM_INSPECTION = "system_inspection"


@dataclass
class SubagentContextRef:
    """Bounded parent reference passed into a subagent task."""
    label: str
    content: str

    def to_dict(self) -> Dict[str, str]:
        return {"label": self.label, "content": self.content}


@dataclass
class SubagentTaskRequest:
    """Contract for delegating a scoped investigation to any subagent."""
    subagent_id: str
    parent_investigation_id: str
    profile: SubagentProfile
    objective: str
    success_criteria: List[str] = field(default_factory=list)
    capability_bundles: List[SubagentCapabilityBundle] = field(default_factory=list)
    context_refs: List[SubagentContextRef] = field(default_factory=list)
    max_steps: int = 15
    timeout_seconds: float = 120.0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subagent_id": self.subagent_id,
            "parent_investigation_id": self.parent_investigation_id,
            "profile": self.profile.value,
            "objective": self.objective,
            "success_criteria": self.success_criteria,
            "capability_bundles": [b.value for b in self.capability_bundles],
            "context_refs": [r.to_dict() for r in self.context_refs],
            "max_steps": self.max_steps,
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at,
        }


@dataclass
class SubagentStructuredResult:
    """Standardized delivery result returned by every subagent to the parent agent."""
    subagent_id: str
    profile: str
    verdict: SubagentVerdict
    confidence: ValidationConfidence
    summary: str
    evidence: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    steps_executed: int = 0
    duration_seconds: float = 0.0
    settled_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subagent_id": self.subagent_id,
            "profile": self.profile,
            "verdict": self.verdict.value,
            "confidence": self.confidence.value,
            "summary": self.summary,
            "evidence": self.evidence,
            "findings": self.findings,
            "steps_executed": self.steps_executed,
            "duration_seconds": round(self.duration_seconds, 2),
            "settled_at": self.settled_at,
        }
