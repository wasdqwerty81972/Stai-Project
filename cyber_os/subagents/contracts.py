"""
cyber_os/subagents/contracts.py — SVS-Cyber Subagent Framework Contracts

Formal schemas, data contracts, and status definitions for defensive specialist subagents.
Adapted from mature agent subagent architecture for SVS-Cyber.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class SubagentProfile(str, Enum):
    THREAT_ANALYSIS = "threat_analysis"
    MALWARE_ANALYSIS = "malware_analysis"
    INCIDENT_INVESTIGATION = "incident_investigation"
    LOG_ANALYSIS = "log_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    DETECTION_ENGINEERING = "detection_engineering"
    FORENSICS_EVIDENCE = "forensics_evidence"
    REMEDIATION_PLANNING = "remediation_planning"
    SECURITY_RESEARCH = "security_research"
    GENERAL = "general"


class SubagentStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    FINALIZING = "finalizing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class SubagentVerdict(str, Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class ValidationConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SubagentCapabilityBundle(str, Enum):
    CODE_READ = "code_read"
    DIAGNOSTIC_TERMINAL = "diagnostic_terminal"
    THREAT_INTEL = "threat_intel"
    SYSTEM_INSPECTION = "system_inspection"
    EVIDENCE_COLLECTION = "evidence_collection"
    WEB_RESEARCH = "web_research"


# Limits and budgets
MAX_SUBAGENT_CONTEXT_REFS = 8
MAX_SUBAGENT_STEPS = 15
MAX_SUBAGENT_WAIT_SECONDS = 180.0
MAX_ACTIVE_SUBAGENTS_PER_PARENT = 3


@dataclass
class SubagentContextRef:
    label: str
    content: str


@dataclass
class SubagentTaskRequest:
    subagent_id: str
    parent_investigation_id: str
    profile: SubagentProfile
    objective: str
    success_criteria: List[str] = field(default_factory=list)
    capability_bundles: List[SubagentCapabilityBundle] = field(default_factory=list)
    context_refs: List[SubagentContextRef] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    timeout_seconds: float = MAX_SUBAGENT_WAIT_SECONDS
    max_steps: int = MAX_SUBAGENT_STEPS


@dataclass
class SubagentStructuredResult:
    subagent_id: str
    profile: str
    status: SubagentStatus
    verdict: SubagentVerdict
    confidence: ValidationConfidence
    summary: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    tool_calls_count: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subagent_id": self.subagent_id,
            "profile": self.profile,
            "status": self.status.value if isinstance(self.status, SubagentStatus) else str(self.status),
            "verdict": self.verdict.value if isinstance(self.verdict, SubagentVerdict) else str(self.verdict),
            "confidence": self.confidence.value if isinstance(self.confidence, ValidationConfidence) else str(self.confidence),
            "summary": self.summary,
            "findings": self.findings,
            "evidence_refs": self.evidence_refs,
            "limitations": self.limitations,
            "recommended_actions": self.recommended_actions,
            "tool_calls_count": self.tool_calls_count,
            "duration_seconds": round(self.duration_seconds, 2),
            "error": self.error,
        }
