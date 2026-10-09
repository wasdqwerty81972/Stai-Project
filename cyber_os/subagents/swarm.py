"""Bounded, defensive-only planning for SVS-Cyber specialist swarms.

Planning is deliberately deterministic: choosing a team must not consume model
credits or turn an ordinary explanatory question into an expensive workflow.
Execution and any containment recommendation remain parent-agent responsibilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List

from cyber_os.subagents.contracts import (
    MAX_ACTIVE_SUBAGENTS_PER_PARENT,
    SubagentProfile,
)


@dataclass(frozen=True)
class DefensiveSwarmPlan:
    objective: str
    profiles: List[SubagentProfile]
    read_only: bool = True
    max_concurrency: int = MAX_ACTIVE_SUBAGENTS_PER_PARENT
    reason: str = "No multi-domain defensive investigation is required."
    rejected_profiles: List[str] = field(default_factory=list)


@dataclass
class DefensiveSwarmExecution:
    """Parent-owned result envelope; child agents never answer the user directly."""

    plan: DefensiveSwarmPlan
    results: List[Any] = field(default_factory=list)

    @property
    def completed_count(self) -> int:
        return sum(getattr(result, "status", None) == "completed" or getattr(getattr(result, "status", None), "value", None) == "completed" for result in self.results)

    @property
    def failed_count(self) -> int:
        return len(self.results) - self.completed_count


@dataclass(frozen=True)
class MergedSwarmEvidence:
    """Evidence-first settlement that a parent can safely synthesize later."""

    summary: str
    coverage: str
    evidence_refs: List[str]
    findings: List[Dict[str, Any]]
    limitations: List[str]
    confirmed_profiles: List[str]
    inconclusive_profiles: List[str]
    failed_profiles: List[str]


def merge_swarm_evidence(execution: DefensiveSwarmExecution) -> MergedSwarmEvidence:
    """Merge child outcomes without turning uncertainty into a finding.

    This reducer intentionally makes no model call. It preserves provenance in
    profile lists and returns the raw verified evidence references for the
    parent agent's later, evidence-bound response.
    """
    evidence_refs: List[str] = []
    findings: List[Dict[str, Any]] = []
    limitations: List[str] = []
    confirmed: List[str] = []
    inconclusive: List[str] = []
    failed: List[str] = []
    seen_evidence = set()

    for result in execution.results:
        profile = str(getattr(result, "profile", "Specialist"))
        status = getattr(getattr(result, "status", None), "value", getattr(result, "status", "failed"))
        verdict = getattr(getattr(result, "verdict", None), "value", getattr(result, "verdict", "inconclusive"))
        if status != "completed":
            failed.append(profile)
            limitations.append(f"{profile} did not complete.")
        elif verdict == "confirmed":
            confirmed.append(profile)
        else:
            inconclusive.append(profile)

        for ref in getattr(result, "evidence_refs", []) or []:
            if ref not in seen_evidence:
                seen_evidence.add(ref)
                evidence_refs.append(ref)
        findings.extend(getattr(result, "findings", []) or [])
        limitations.extend(str(item) for item in (getattr(result, "limitations", []) or []) if item)

    if failed or inconclusive:
        coverage = "incomplete"
    elif len(confirmed) >= 2 and evidence_refs:
        coverage = "multiple_sources"
    elif evidence_refs:
        coverage = "preliminary"
    else:
        coverage = "incomplete"

    summary = (
        f"Swarm evidence: {len(confirmed)} confirmed, {len(inconclusive)} inconclusive, "
        f"{len(failed)} unavailable specialist result(s)."
    )
    return MergedSwarmEvidence(
        summary=summary,
        coverage=coverage,
        evidence_refs=evidence_refs,
        findings=findings,
        limitations=list(dict.fromkeys(limitations)),
        confirmed_profiles=confirmed,
        inconclusive_profiles=inconclusive,
        failed_profiles=failed,
    )


class DefensiveSwarmPlanner:
    """Select only relevant vetted defensive specialists for an investigation."""

    _KEYWORD_PROFILES = (
        (
            ("incident", "ransomware", "breach", "lateral movement", "power shell", "powershell"),
            SubagentProfile.INCIDENT_INVESTIGATION,
        ),
        (
            ("network", "connection", "beacon", "c2", "domain", " ip ", "traffic"),
            SubagentProfile.NETWORK_ANALYSIS,
        ),
        (
            ("malware", "binary", "payload", "script", "powershell", "hash", ".exe", ".dll"),
            SubagentProfile.MALWARE_ANALYSIS,
        ),
        (
            ("log", "event id", "sysmon", "failed login", "authentication"),
            SubagentProfile.LOG_ANALYSIS,
        ),
        (
            ("ioc", "hash", "ip", "domain", "indicator", "threat intel"),
            SubagentProfile.THREAT_ANALYSIS,
        ),
    )

    def plan(
        self,
        objective: str,
        requested_profiles: Iterable[str] | None = None,
    ) -> DefensiveSwarmPlan:
        """Return a small, read-only team only when the request warrants one."""
        text = f" {objective.lower()} "
        profiles: List[SubagentProfile] = []
        rejected: List[str] = []

        for requested in requested_profiles or []:
            try:
                profile = SubagentProfile(str(requested).strip())
            except ValueError:
                rejected.append(str(requested))
                continue
            if profile is not SubagentProfile.GENERAL and profile not in profiles:
                profiles.append(profile)

        if not profiles:
            for keywords, profile in self._KEYWORD_PROFILES:
                if any(keyword in text for keyword in keywords) and profile not in profiles:
                    profiles.append(profile)

        # A swarm is meaningful only when at least two independent domains can
        # validate each other. Keep one-profile work on the normal agent path.
        if len(profiles) < 2 and not requested_profiles:
            profiles = []

        profiles = profiles[:MAX_ACTIVE_SUBAGENTS_PER_PARENT]
        if profiles:
            reason = "Selected complementary defensive specialists for a multi-domain investigation."
        else:
            reason = "No multi-domain defensive investigation is required."
        return DefensiveSwarmPlan(
            objective=objective,
            profiles=profiles,
            reason=reason,
            rejected_profiles=rejected,
        )
