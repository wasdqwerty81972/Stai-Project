"""
cyber_os/subagents/profiles.py — SVS-Cyber Defensive Specialist Subagent Profiles

Defines 10 specialized defensive cybersecurity agent roles with explicit scopes,
system prompts, tool whitelists, and bounded capabilities.
Adapted from mature agent subagent architecture for SVS-Cyber.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from cyber_os.subagents.contracts import (
    SubagentCapabilityBundle,
    SubagentProfile,
)


@dataclass
class SpecialistProfileDefinition:
    profile: SubagentProfile
    name: str
    icon: str
    specialization: str
    system_prompt: str
    allowed_tools: List[str]
    capability_bundles: List[SubagentCapabilityBundle]
    max_steps: int = 12


DEFENSIVE_SPECIALIST_PROFILES: Dict[SubagentProfile, SpecialistProfileDefinition] = {
    SubagentProfile.THREAT_ANALYSIS: SpecialistProfileDefinition(
        profile=SubagentProfile.THREAT_ANALYSIS,
        name="Threat Analysis Specialist",
        icon="🌐",
        specialization="IOC correlation, threat actor attribution, OSINT, and threat intelligence feeds",
        system_prompt=(
            "You are SVS-Cyber's Threat Analysis Specialist. Your mission is to evaluate indicators "
            "of compromise (IPs, domains, file hashes, URLs), correlate with known threat campaigns, "
            "and determine threat confidence. Distinguish known malicious artifacts from benign infrastructure. "
            "Never invent detections or claim feeds returned positive indicators without evidence. "
            "Deliver a structured verdict with confidence and recommended defensive mitigations."
        ),
        allowed_tools=[
            "virustotal_hash_lookup",
            "virustotal_ip_lookup",
            "otx_ip_lookup",
            "enrich_artifact",
            "web_search",
        ],
        capability_bundles=[SubagentCapabilityBundle.THREAT_INTEL, SubagentCapabilityBundle.WEB_RESEARCH],
        max_steps=10,
    ),
    SubagentProfile.MALWARE_ANALYSIS: SpecialistProfileDefinition(
        profile=SubagentProfile.MALWARE_ANALYSIS,
        name="Malware Analysis Specialist",
        icon="🦠",
        specialization="Binary and script behavioral analysis, disassembly indicators, entropy, and malware family identification",
        system_prompt=(
            "You are SVS-Cyber's Malware Analysis Specialist. Your mission is to inspect files, "
            "scripts, and suspicious binaries. Evaluate PE headers, entropy, embedded strings, "
            "obfuscation techniques, and simulated execution behavior. Never execute uncontrolled "
            "malware directly on the host. Deliver clear technical evidence and IOCs."
        ),
        allowed_tools=[
            "static_analysis",
            "entropy_check",
            "workspace_read_file",
            "shell_exec",
        ],
        capability_bundles=[SubagentCapabilityBundle.CODE_READ, SubagentCapabilityBundle.EVIDENCE_COLLECTION],
        max_steps=12,
    ),
    SubagentProfile.INCIDENT_INVESTIGATION: SpecialistProfileDefinition(
        profile=SubagentProfile.INCIDENT_INVESTIGATION,
        name="Incident Investigation Specialist",
        icon="🔍",
        specialization="Attack timeline reconstruction, root cause analysis, blast radius estimation, and MITRE mapping",
        system_prompt=(
            "You are SVS-Cyber's Incident Investigation Specialist. Your mission is to correlate multi-source "
            "evidence across files, processes, and network events into a cohesive attack timeline. "
            "Map observations to MITRE ATT&CK tactics and techniques. Distinguish verified facts from working hypotheses."
        ),
        allowed_tools=[
            "workspace_read_file",
            "workspace_list_files",
            "network_inspect",
            "shell_exec",
            "notes",
        ],
        capability_bundles=[SubagentCapabilityBundle.SYSTEM_INSPECTION, SubagentCapabilityBundle.CODE_READ],
        max_steps=14,
    ),
    SubagentProfile.LOG_ANALYSIS: SpecialistProfileDefinition(
        profile=SubagentProfile.LOG_ANALYSIS,
        name="Log Analysis Specialist",
        icon="📜",
        specialization="Windows Event Log, Sysmon, auth log, and security event correlation",
        system_prompt=(
            "You are SVS-Cyber's Log Analysis Specialist. Your mission is to analyze security event logs, "
            "identify anomalous authentication patterns, brute-force attempts, privilege escalation, "
            "and service installation events. Extract timestamped evidence with event IDs."
        ),
        allowed_tools=[
            "workspace_read_file",
            "secret_scan",
            "shell_exec",
        ],
        capability_bundles=[SubagentCapabilityBundle.CODE_READ, SubagentCapabilityBundle.DIAGNOSTIC_TERMINAL],
        max_steps=10,
    ),
    SubagentProfile.NETWORK_ANALYSIS: SpecialistProfileDefinition(
        profile=SubagentProfile.NETWORK_ANALYSIS,
        name="Network Defense Specialist",
        icon="📡",
        specialization="Active connections, listening ports, protocol anomalies, beaconing, and DNS analysis",
        system_prompt=(
            "You are SVS-Cyber's Network Defense Specialist. Your mission is to inspect active local "
            "network sockets, listening endpoints, and external connections. Identify potential C2 "
            "beaconing, unexpected listening services, or unauthorized lateral connections."
        ),
        allowed_tools=[
            "network_inspect",
            "shell_exec",
        ],
        capability_bundles=[SubagentCapabilityBundle.SYSTEM_INSPECTION, SubagentCapabilityBundle.DIAGNOSTIC_TERMINAL],
        max_steps=10,
    ),
    SubagentProfile.VULNERABILITY_ANALYSIS: SpecialistProfileDefinition(
        profile=SubagentProfile.VULNERABILITY_ANALYSIS,
        name="Vulnerability Analysis Specialist",
        icon="🛡️",
        specialization="CVE assessment, software inventory auditing, and exploitability analysis",
        system_prompt=(
            "You are SVS-Cyber's Vulnerability Analysis Specialist. Your mission is to assess detected "
            "software versions and configurations against known CVEs and CISA KEV listings. "
            "Do NOT exploit vulnerabilities. Determine whether a vulnerability is practically exposed and recommend remediation."
        ),
        allowed_tools=[
            "workspace_read_file",
            "static_analysis",
            "web_search",
        ],
        capability_bundles=[SubagentCapabilityBundle.CODE_READ, SubagentCapabilityBundle.WEB_RESEARCH],
        max_steps=10,
    ),
    SubagentProfile.DETECTION_ENGINEERING: SpecialistProfileDefinition(
        profile=SubagentProfile.DETECTION_ENGINEERING,
        name="Detection Engineering Specialist",
        icon="⚙️",
        specialization="Sigma rule authoring, Yara signatures, Defender queries, and detection coverage validation",
        system_prompt=(
            "You are SVS-Cyber's Detection Engineering Specialist. Your mission is to convert investigated "
            "threat patterns and IOCs into actionable, robust detection rules (Sigma, Yara, or EDR queries). "
            "Ensure low false-positive rates and include clear test criteria."
        ),
        allowed_tools=[
            "workspace_read_file",
            "static_analysis",
        ],
        capability_bundles=[SubagentCapabilityBundle.CODE_READ],
        max_steps=8,
    ),
    SubagentProfile.FORENSICS_EVIDENCE: SpecialistProfileDefinition(
        profile=SubagentProfile.FORENSICS_EVIDENCE,
        name="Forensics & Evidence Specialist",
        icon="🔬",
        specialization="Digital artifact preservation, hash generation, file metadata, and chain-of-custody tracking",
        system_prompt=(
            "You are SVS-Cyber's Forensics & Evidence Specialist. Your mission is to collect and preserve "
            "digital artifacts, calculate SHA-256 hashes, record creation/modification timestamps, "
            "and ensure chain of custody for all evidence discovered during the investigation."
        ),
        allowed_tools=[
            "static_analysis",
            "workspace_read_file",
            "workspace_list_files",
        ],
        capability_bundles=[SubagentCapabilityBundle.EVIDENCE_COLLECTION, SubagentCapabilityBundle.CODE_READ],
        max_steps=10,
    ),
    SubagentProfile.REMEDIATION_PLANNING: SpecialistProfileDefinition(
        profile=SubagentProfile.REMEDIATION_PLANNING,
        name="Remediation Planning Specialist",
        icon="🩹",
        specialization="Defensive containment, process isolation, rule modification, and recovery planning",
        system_prompt=(
            "You are SVS-Cyber's Remediation Planning Specialist. Your mission is to develop step-by-step "
            "containment and remediation procedures. Specify exact actions required (e.g. firewall block, "
            "patch application, configuration fix). Note which actions require administrator authorization."
        ),
        allowed_tools=[
            "workspace_read_file",
            "notes",
        ],
        capability_bundles=[SubagentCapabilityBundle.CODE_READ],
        max_steps=8,
    ),
    SubagentProfile.SECURITY_RESEARCH: SpecialistProfileDefinition(
        profile=SubagentProfile.SECURITY_RESEARCH,
        name="Security Research Specialist",
        icon="📚",
        specialization="Advisory verification, vendor patch bulletins, zero-day research, and security literature",
        system_prompt=(
            "You are SVS-Cyber's Security Research Specialist. Your mission is to query security advisories, "
            "vendor release notes, and authoritative documentation to verify novel threat techniques, "
            "patch availability, and mitigation guidance."
        ),
        allowed_tools=[
            "web_search",
        ],
        capability_bundles=[SubagentCapabilityBundle.WEB_RESEARCH],
        max_steps=8,
    ),
}


def get_profile_definition(profile: SubagentProfile) -> SpecialistProfileDefinition:
    """Returns the profile definition, falling back to General if not found."""
    if profile in DEFENSIVE_SPECIALIST_PROFILES:
        return DEFENSIVE_SPECIALIST_PROFILES[profile]
    # Fallback to Threat Analysis
    return DEFENSIVE_SPECIALIST_PROFILES[SubagentProfile.THREAT_ANALYSIS]


# --- Markdown-defined subagents (subagents/definitions/) ---------------------
#
# The ten profiles above are hand-written with curated defensive allowlists.
# ``subagents/definitions/*.md`` supplies many more, loaded at runtime by
# cyber_os.assets.agents. Resolution below prefers the hand-written profile on
# any name clash, because only that one has a vetted tool allowlist.

# SVS tool -> capability bundle, so a markdown definition's translated tool
# access implies the same bundles the hand-written profiles declare explicitly.
_TOOL_CAPABILITY_BUNDLES: Dict[str, SubagentCapabilityBundle] = {
    "workspace_read_file": SubagentCapabilityBundle.CODE_READ,
    "workspace_list_files": SubagentCapabilityBundle.CODE_READ,
    "shell_exec": SubagentCapabilityBundle.DIAGNOSTIC_TERMINAL,
    "web_search": SubagentCapabilityBundle.WEB_RESEARCH,
}


def _bundles_for_tools(tools: List[str]) -> List[SubagentCapabilityBundle]:
    """Derive capability bundles from a resolved SVS tool allowlist."""
    bundles: List[SubagentCapabilityBundle] = []
    for tool in tools:
        bundle = _TOOL_CAPABILITY_BUNDLES.get(tool)
        if bundle is not None and bundle not in bundles:
            bundles.append(bundle)
    return bundles


def definition_to_profile(definition: Any) -> SpecialistProfileDefinition:
    """Adapt a :class:`cyber_os.assets.agents.AgentDefinition` to a profile.

    Markdown definitions have no ``SubagentProfile`` enum member of their own —
    the enum is a closed set of the ten defensive specialists — so they carry
    ``SubagentProfile.GENERAL`` as the enum and keep their real identity in
    ``name``. Capabilities the definition could not be granted are appended to
    the system prompt so the subagent does not act as though it has them.
    """
    allowed_tools = list(definition.allowed_tools)
    notes = definition.capability_notes()

    system_prompt = definition.system_prompt()
    if notes:
        system_prompt = (
            f"{system_prompt}\n\n"
            "<capability_limits>\n"
            "Capabilities declared by this definition that are unavailable in "
            "this deployment:\n"
            + "\n".join(f"- {note}" for note in notes)
            + "\nDo not claim results that would require them.\n"
            "</capability_limits>"
        )

    return SpecialistProfileDefinition(
        profile=SubagentProfile.GENERAL,
        name=definition.name,
        icon="📄",
        specialization=definition.description,
        system_prompt=system_prompt,
        allowed_tools=allowed_tools,
        capability_bundles=_bundles_for_tools(allowed_tools),
        max_steps=definition.max_steps,
    )


def resolve_profile_definition(
    profile_name: str,
) -> Tuple[SubagentProfile, SpecialistProfileDefinition, str]:
    """Resolve a delegation target by name.

    Returns ``(profile_enum, definition, origin)`` where ``origin`` is one of
    ``"builtin"``, ``"markdown_definition"``, or ``"fallback"``.

    Previously an unrecognised name silently became Threat Analysis, so
    delegating to a markdown-defined agent ran a different specialist than the
    caller asked for. Markdown definitions are now resolved properly, and the
    legacy fallback is still reported as ``"fallback"`` so callers can tell the
    difference.
    """
    cleaned = (profile_name or "").strip()

    # 1. Hand-written defensive specialist. Wins any name clash.
    try:
        profile_enum = SubagentProfile(cleaned)
    except ValueError:
        profile_enum = None
    if profile_enum is not None and profile_enum in DEFENSIVE_SPECIALIST_PROFILES:
        return profile_enum, DEFENSIVE_SPECIALIST_PROFILES[profile_enum], "builtin"

    # 2. Markdown definition. Imported lazily: cyber_os.assets reads the
    #    filesystem, and profiles.py is imported during agent construction.
    if cleaned:
        try:
            from cyber_os.assets.agents import get_agent_definition_registry

            definition = get_agent_definition_registry().get(cleaned)
        except Exception:
            definition = None
        if definition is not None:
            return (
                SubagentProfile.GENERAL,
                definition_to_profile(definition),
                "markdown_definition",
            )

    # 3. Legacy behaviour, now labelled so the caller can surface it.
    return (
        SubagentProfile.THREAT_ANALYSIS,
        DEFENSIVE_SPECIALIST_PROFILES[SubagentProfile.THREAT_ANALYSIS],
        "fallback",
    )


def list_available_profiles() -> List[Dict[str, Any]]:
    """Returns a list of all specialist profiles for UI selection and agent tool descriptions."""
    return [
        {
            "id": p.profile.value,
            "name": p.name,
            "icon": p.icon,
            "specialization": p.specialization,
            "allowed_tools": p.allowed_tools,
            "origin": "builtin",
        }
        for p in DEFENSIVE_SPECIALIST_PROFILES.values()
    ]
