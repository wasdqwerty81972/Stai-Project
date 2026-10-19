"""
subagents/registry.py — Unified Subagent Registry

Maps all subagent profiles (both core autonomous task workers and SVS-Cyber specialists)
to their concrete subagent implementations.
"""

from __future__ import annotations

from typing import Any, Dict, List, Type

from subagents.base import BaseSubagent
from subagents.contracts import SubagentProfile
from subagents.cyber.specialists import (
    DetectionEngineeringSubagent,
    ForensicsInvestigationSubagent,
    IncidentInvestigationSubagent,
    LogAnalysisSubagent,
    MalwareAnalysisSubagent,
    NetworkDefenseSubagent,
    RemediationPlanningSubagent,
    SecurityResearchSubagent,
    ThreatAnalysisSubagent,
    VulnerabilityAnalysisSubagent,
)
from subagents.core.general import GeneralWorkerSubagent
from subagents.core.security_task import SecurityTaskSubagent
from subagents.core.validation import ValidationSubagent

SUBAGENT_REGISTRY: Dict[SubagentProfile, Type[BaseSubagent]] = {
    # Core Autonomous Workers
    SubagentProfile.GENERAL: GeneralWorkerSubagent,
    SubagentProfile.SECURITY_TASK: SecurityTaskSubagent,
    SubagentProfile.SECURITY_VALIDATION: ValidationSubagent,

    # SVS-Cyber Defensive Specialists
    SubagentProfile.THREAT_ANALYSIS: ThreatAnalysisSubagent,
    SubagentProfile.MALWARE_ANALYSIS: MalwareAnalysisSubagent,
    SubagentProfile.INCIDENT_INVESTIGATION: IncidentInvestigationSubagent,
    SubagentProfile.LOG_ANALYSIS: LogAnalysisSubagent,
    SubagentProfile.NETWORK_DEFENSE: NetworkDefenseSubagent,
    SubagentProfile.VULNERABILITY_ANALYSIS: VulnerabilityAnalysisSubagent,
    SubagentProfile.DETECTION_ENGINEERING: DetectionEngineeringSubagent,
    SubagentProfile.FORENSICS_INVESTIGATION: ForensicsInvestigationSubagent,
    SubagentProfile.REMEDIATION_PLANNING: RemediationPlanningSubagent,
    SubagentProfile.SECURITY_RESEARCH: SecurityResearchSubagent,
}


def get_subagent_class(profile: SubagentProfile | str) -> Type[BaseSubagent]:
    """Resolves a profile string or enum to its concrete Subagent class."""
    if isinstance(profile, str):
        try:
            profile = SubagentProfile(profile)
        except ValueError:
            profile = SubagentProfile.THREAT_ANALYSIS
    return SUBAGENT_REGISTRY.get(profile, ThreatAnalysisSubagent)


def list_all_subagents() -> List[Dict[str, Any]]:
    """Returns metadata for all available subagents."""
    subagents = []
    for profile, cls in SUBAGENT_REGISTRY.items():
        subagents.append({
            "profile": profile.value,
            "name": cls.name,
            "icon": cls.icon,
            "description": cls.description,
            "allowed_tools": list(cls.allowed_tools),
            "capability_bundles": [b.value for b in cls.capability_bundles],
            "max_steps": cls.max_steps,
            "origin": "svs_core" if "core" in cls.__module__ else "svs_cyber",
        })
    return subagents
