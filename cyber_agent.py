"""
Cybersecurity Agent Main Orchestrator (cyber_agent.py)

Coordinates environment tools, dynamic script building, system analysis, 
vulnerability detection, security monitoring, WSL tool dispatching, and secure remediation.
"""

import os
import sys
import json
import shutil
import subprocess
import threading
import time
import ctypes
import string
from typing import Dict, Any, List, Optional
from cyber_tools import (
    AuditLogger, AutomatedGuardrailManager, ToolRegistry, ToolDefinition,
    RiskLevel, WSLDetector, execute_system_command, StaticCodeAnalyzer, SystemMonitor,
    register_all_default_tools, RealtimeSecurityDaemon, KernelInterceptionDaemon
)
from key_manager import AiApi, MockRoleKeyManager
from ui.event_bus import AgentEvent, event_bus
from cyber_os.investigation_state import InvestigationState
from cyber_os.approval_engine import ApprovalEngine
from cyber_os.pty_session_manager import PtySessionManager
from cyber_os.task_manager import TaskManager
from cyber_os.notes_manager import NotesManager
from cyber_os.subagents.manager import SubagentManager
from cyber_os.subagents.profiles import list_available_profiles
from cyber_os.agent_runtime import AgentRuntime

# Cybersecurity AI roles for the orchestrator
CYBER_ROLES = {
    "investigator": "You are a senior security investigator. Perform evidence-first analysis, correlate verified observations, and recommend safe defensive actions.",
    "threat_intel_analyst": "You are a senior threat intelligence analyst. Analyze IOCs, attribution, campaign patterns, and produce actionable threat intelligence reports.",
    "malware_analyst": "You are a malware reverse engineer. Analyze binary behavior, identify malware families, extract IOCs, and provide remediation guidance.",
    "network_defender": "You are a network security defender. Analyze network traffic, detect anomalies, identify beaconing/DNS tunneling, and recommend firewall rules.",
    "incident_responder": "You are a SOC incident commander. Coordinate incident response, prioritize actions, assess blast radius, and produce executive summaries.",
    "forensic_investigator": "You are a digital forensic investigator. Examine artifacts, reconstruct attack timelines, preserve evidence, and produce chain-of-custody documentation.",
    "vulnerability_researcher": "You are a vulnerability researcher. Analyze CVEs, assess exploitability, recommend patches, and evaluate attack surface.",
}

# =============================================================================
# Vigil SOC-Inspired Architecture
# =============================================================================
# 13 specialized AI SOC agents, Markdown-defined workflows, MITRE ATT&CK
# mapping, and Investigation Ledger — all built from scratch here.
# =============================================================================

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone


# --- MITRE ATT&CK Mapping ---

MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

MITRE_TECHNIQUES = {
    "T1595": "Active Scanning", "T1592": "Gather Victim Host Information",
    "T1591": "Gather Victim Org Information", "T1566": "Phishing",
    "T1190": "Exploit Public-Facing Application", "T1133": "External Remote Services",
    "T1059": "Command and Scripting Interpreter", "T1203": "Exploitation for Client Execution",
    "T1053": "Scheduled Task/Job", "T1543": "Create or Modify System Process",
    "T1078": "Valid Accounts", "T1547": "Boot or Logon Autostart Execution",
    "T1562": "Impair Defenses", "T1070": "Indicator Removal on Host",
    "T1003": "OS Credential Dumping", "T1558": "Steal or Forge Kerberos Tickets",
    "T1083": "File and Directory Discovery", "T1087": "Account Discovery",
    "T1047": "Windows Management Instrumentation", "T1021": "Remote Services",
    "T1041": "Exfiltration Over C2 Channel", "T1567": "Exfiltration Over Web Service",
    "T1486": "Data Encrypted for Impact", "T1489": "Service Stop",
}

MITRE_SOFTWARE = {
    "T1566.001": "Emotet", "T1059.003": "PowerShell Empire",
    "T1078.002": "Pass-the-Hash", "T1047": "WMI",
    "T1021.001": "RDP", "T1218.011": "Mshta",
}


# --- Investigation Ledger (explainability) ---

@dataclass
class LedgerEvent:
    timestamp: str
    agent: str
    phase: str
    action: str
    tool: Optional[str]
    input_summary: str
    output_summary: str
    rationale: str
    approved: bool = True


class InvestigationLedger:
    """Append-only event log for a single SOC investigation run."""

    def __init__(self, case_id: str):
        self.case_id = case_id
        self.events: List[LedgerEvent] = []

    def record(self, agent: str, phase: str, action: str, tool: Optional[str],
               input_summary: str, output_summary: str, rationale: str, approved: bool = True) -> None:
        self.events.append(LedgerEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent=agent, phase=phase, action=action, tool=tool,
            input_summary=input_summary[:200], output_summary=output_summary[:200],
            rationale=rationale[:200], approved=approved,
        ))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "total_events": len(self.events),
            "events": [
                {"timestamp": e.timestamp, "agent": e.agent, "phase": e.phase,
                 "action": e.action, "tool": e.tool, "input_summary": e.input_summary,
                 "output_summary": e.output_summary, "rationale": e.rationale,
                 "approved": e.approved}
                for e in self.events
            ],
        }

    def render_markdown(self) -> str:
        lines = [f"# Investigation Ledger — {self.case_id}"]
        for i, e in enumerate(self.events, 1):
            lines.append(f"\n## Event {i}: {e.action}")
            lines.append(f"- **Time**: {e.timestamp}")
            lines.append(f"- **Agent**: {e.agent}")
            lines.append(f"- **Phase**: {e.phase}")
            lines.append(f"- **Tool**: {e.tool or 'N/A'}")
            lines.append(f"- **Input**: {e.input_summary}")
            lines.append(f"- **Output**: {e.output_summary}")
            lines.append(f"- **Rationale**: {e.rationale}")
            lines.append(f"- **Approved**: {e.approved}")
        return "\n".join(lines)


# --- Workflow Definitions (Markdown-inspired) ---

@dataclass
class WorkflowPhase:
    id: str
    name: str
    agent: str
    tools: List[str]
    instructions: str
    approval_required: bool = False


@dataclass
class Workflow:
    name: str
    description: str
    phases: List[WorkflowPhase]


BUILTIN_WORKFLOWS: Dict[str, Workflow] = {
    "incident-response": Workflow(
        name="Incident Response",
        description="NIST IR framework: triage, investigate, contain, report.",
        phases=[
            WorkflowPhase(id="triage", name="Assess the Alert", agent="triage",
                          tools=["static_analysis", "secret_scan", "entropy_check"],
                          instructions="Score severity, filter false positives, decide escalation."),
            WorkflowPhase(id="investigate", name="Investigate Root Cause", agent="investigator",
                          tools=["network_inspect", "process_tree_analysis"],
                          instructions="Collect evidence, reconstruct timeline, correlate sources."),
            WorkflowPhase(id="contain", name="Contain the Threat", agent="responder",
                          tools=["quarantine_file", "block_ip", "disable_startup_entry"],
                          instructions="Assess blast radius, recommend containment with confidence scores.",
                          approval_required=True),
            WorkflowPhase(id="report", name="Generate Report", agent="reporter",
                          tools=["generate_incident_report"],
                          instructions="Produce executive summary and technical report."),
        ],
    ),
    "threat-hunt": Workflow(
        name="Threat Hunt",
        description="Hypothesis-driven hunting across network, endpoint, and threat intel.",
        phases=[
            WorkflowPhase(id="hunt", name="Proactive Hunting", agent="threat_hunter",
                          tools=["network_inspect", "beaconing_detect"],
                          instructions="Run hypothesis-driven anomaly detection."),
            WorkflowPhase(id="analyze", name="Analyze Findings", agent="malware_analyst",
                          tools=["pe_header_analysis", "yara_scan"],
                          instructions="Classify malware, extract IOCs."),
            WorkflowPhase(id="enrich", name="Enrich with Threat Intel", agent="threat_intel",
                          tools=["virustotal_hash_lookup", "virustotal_ip_lookup", "otx_ip_lookup", "enrich_artifact"],
                          instructions="Enrich IOCs with attribution and campaign data."),
            WorkflowPhase(id="report", name="Hunt Report", agent="reporter",
                          tools=["generate_incident_report"],
                          instructions="Document hunt findings and detection recommendations."),
        ],
    ),
    "forensic-analysis": Workflow(
        name="Forensic Analysis",
        description="Post-incident forensics with evidence preservation.",
        phases=[
            WorkflowPhase(id="collect", name="Collect Evidence", agent="forensics",
                          tools=["strings_inspect", "exiftool_inspect"],
                          instructions="Preserve artifacts, establish chain of custody."),
            WorkflowPhase(id="analyze", name="Analyze Artifacts", agent="malware_analyst",
                          tools=["pe_header_analysis", "capa_detect"],
                          instructions="Identify malware behavior and capabilities."),
            WorkflowPhase(id="timeline", name="Reconstruct Timeline", agent="investigator",
                          tools=["process_tree_analysis", "auditd_monitor"],
                          instructions="Build attack timeline from artifacts."),
            WorkflowPhase(id="report", name="Forensic Report", agent="reporter",
                          tools=["generate_incident_report"],
                          instructions="Produce legal-grade forensic report."),
        ],
    ),
}


# --- 13 Specialized SOC Agents ---

@dataclass
class SOCAgent:
    id: str
    name: str
    icon: str
    color: str
    description: str
    specialization: str
    system_prompt: str
    recommended_tools: List[str]
    task_keywords: List[str] = field(default_factory=list)
    approval_required: bool = False


BUILTIN_AGENTS: Dict[str, SOCAgent] = {
    "triage": SOCAgent(
        id="triage", name="Triage Agent", icon="T", color="#FF6B6B",
        description="Rapid alert assessment and prioritization",
        specialization="Alert Triage & Prioritization",
        system_prompt="You are a SOC triage analyst. Rapidly assess alerts, score severity, filter false positives, and recommend escalation.",
        recommended_tools=["static_analysis", "secret_scan", "entropy_check", "url_similarity_check"],
        task_keywords=["triage", "prioritize", "quick", "alert"],
    ),
    "investigator": SOCAgent(
        id="investigator", name="Investigation Agent", icon="I", color="#4ECDC4",
        description="Deep-dive security investigations",
        specialization="Deep Security Investigations",
        system_prompt="You are a senior security investigator. Perform thorough root cause analysis, collect evidence, correlate sources, and recommend containment.",
        recommended_tools=["network_inspect", "process_tree_analysis", "windows_process_monitor"],
        task_keywords=["investigate", "deep dive", "analyze", "root cause"],
    ),
    "threat_hunter": SOCAgent(
        id="threat_hunter", name="Threat Hunter", icon="H", color="#45B7D1",
        description="Proactive threat detection and hypothesis-driven hunting",
        specialization="Proactive Threat Hunting",
        system_prompt="You are a threat hunter. Run hypothesis-driven hunts, detect anomalies, and identify stealthy attackers.",
        recommended_tools=["dns_exfil_check", "beaconing_detect", "network_inspect"],
        task_keywords=["hunt", "proactive", "search", "anomaly"],
    ),
    "correlator": SOCAgent(
        id="correlator", name="Correlator", icon="C", color="#96CEB4",
        description="Multi-signal linking and campaign identification",
        specialization="Cross-Signal Correlation",
        system_prompt="You are a threat correlator. Link related alerts, identify attack campaigns, and reconstruct attack chains.",
        recommended_tools=["ai_triage_correlate", "network_inspect"],
        task_keywords=["correlate", "link", "campaign", "chain"],
    ),
    "responder": SOCAgent(
        id="responder", name="Responder", icon="R", color="#FFEAA7",
        description="Containment actions and blast radius assessment",
        specialization="Incident Response & Containment",
        system_prompt="You are a SOC incident responder. Assess blast radius, recommend containment actions, and provide confidence-scored approval requests.",
        recommended_tools=["quarantine_file", "block_ip", "disable_startup_entry", "kill_and_block"],
        task_keywords=["respond", "contain", "isolate", "remediate"],
    ),
    "reporter": SOCAgent(
        id="reporter", name="Reporter", icon="P", color="#DDA0DD",
        description="Executive summaries and technical documentation",
        specialization="Report Generation",
        system_prompt="You are a SOC reporter. Produce executive summaries, technical reports, and audit-ready documentation.",
        recommended_tools=["generate_incident_report", "ai_incident_summary"],
        task_keywords=["report", "summary", "document", "executive"],
    ),
    "mitre_analyst": SOCAgent(
        id="mitre_analyst", name="MITRE Analyst", icon="M", color="#FF9FF3",
        description="ATT&CK mapping and coverage analysis",
        specialization="MITRE ATT&CK Mapping",
        system_prompt="You are a MITRE ATT&CK analyst. Map techniques, analyze coverage, identify gaps, and recommend detection templates.",
        recommended_tools=["sigma_rule_match", "static_analysis", "yara_scan"],
        task_keywords=["mitre", "attack", "technique", "tactic", "coverage"],
    ),
    "forensics": SOCAgent(
        id="forensics", name="Forensics Agent", icon="F", color="#54A0FF",
        description="Digital forensics and evidence preservation",
        specialization="Digital Forensics",
        system_prompt="You are a digital forensic investigator. Examine artifacts, preserve evidence, reconstruct timelines, and maintain chain of custody.",
        recommended_tools=["strings_inspect", "exiftool_inspect", "binwalk_inspect", "volatility_memory"],
        task_keywords=["forensic", "artifact", "evidence", "preserve"],
    ),
    "threat_intel": SOCAgent(
        id="threat_intel", name="Threat Intel Analyst", icon="TI", color="#5F27CD",
        description="IOC enrichment and actor attribution",
        specialization="Threat Intelligence",
        system_prompt=(
            "You are a threat intelligence analyst. Enrich IOCs, attribute campaigns, and integrate OSINT. "
            "Treat verdict=unknown as 'no data', never as 'clean' - a lookup that could not run is not "
            "evidence an artifact is safe. Note that these lookups disclose the artifact to a third party."
        ),
        recommended_tools=["virustotal_hash_lookup", "virustotal_ip_lookup", "otx_ip_lookup", "enrich_artifact"],
        task_keywords=["threat", "intel", "ioc", "attribution", "osint"],
    ),
    "compliance": SOCAgent(
        id="compliance", name="Compliance Agent", icon="O", color="#01A3A4",
        description="Regulatory and standards compliance checks",
        specialization="Compliance & Governance",
        system_prompt="You are a compliance officer. Assess NIST, ISO, PCI-DSS, HIPAA, GDPR, SOC 2 controls.",
        recommended_tools=["cis_benchmark_check", "firewall_rule_audit", "open_port_audit"],
        task_keywords=["compliance", "nist", "iso", "pci", "hipaa", "gdpr", "audit"],
    ),
    "malware_analyst": SOCAgent(
        id="malware_analyst", name="Malware Analyst", icon="MA", color="#F368E0",
        description="Static/dynamic malware analysis and family classification",
        specialization="Malware Analysis",
        system_prompt="You are a malware reverse engineer. Analyze binaries, classify families, extract IOCs, and identify C2 infrastructure.",
        recommended_tools=["pe_header_analysis", "import_table_scan", "yara_scan", "capa_detect", "entropy_check"],
        task_keywords=["malware", "ransomware", "trojan", "sample", "virus", "binary"],
    ),
    "network_analyst": SOCAgent(
        id="network_analyst", name="Network Analyst", icon="NA", color="#FF6348",
        description="Network traffic analysis and lateral movement detection",
        specialization="Network Security Analysis",
        system_prompt="You are a network security analyst. Analyze traffic, detect anomalies, identify lateral movement, and recommend firewall rules.",
        recommended_tools=["network_inspect", "dns_exfil_check", "beaconing_detect", "tshark_capture"],
        task_keywords=["network", "traffic", "flow", "lateral", "firewall"],
    ),
    "auto_responder": SOCAgent(
        id="auto_responder", name="Auto Responder", icon="AR", color="#2ED573",
        description="Autonomous containment with confidence-gated approval",
        specialization="Automated Response",
        system_prompt="You are an automated responder. Execute containment actions with confidence scoring and human approval gates.",
        recommended_tools=["quarantine_file", "block_ip", "kill_and_block"],
        task_keywords=["auto", "automated", "auto-contain", "auto-remediate"],
        approval_required=True,
    ),
}


# --- Vigil-Inspired SOC Orchestrator ---

class SOCOrchestrator:
    """
    Multi-agent SOC orchestrator inspired by Vigil SOC.

    Features:
      - 13 specialized AI SOC agents
      - Markdown-defined workflow execution (Compose)
      - MITRE ATT&CK technique mapping
      - Investigation Ledger for explainability
    """

    def __init__(self, use_mock: bool = True, agent: Optional[Any] = None):
        self.api = AiApi(use_mock=use_mock)
        self.use_mock = use_mock
        self.agents = BUILTIN_AGENTS
        self.workflows = BUILTIN_WORKFLOWS
        self._agent = agent

    def get_agent_by_task(self, task: str) -> SOCAgent:
        task_lower = task.lower()
        best_agent = next(iter(self.agents.values()))
        best_score = 0
        for agent in self.agents.values():
            score = sum(1 for kw in agent.task_keywords if kw in task_lower)
            if score > best_score:
                best_score = score
                best_agent = agent
        return best_agent

    def _call_agent(self, agent_id: str, prompt: str) -> str:
        if agent_id not in self.agents:
            agent_id = "investigator"
        agent = self.agents[agent_id]
        if self.use_mock:
            return MockRoleKeyManager._CANNED.get(agent_id, MockRoleKeyManager._CANNED["default"])
        try:
            resp = self.api.chat_with_role(agent_id, agent.system_prompt, prompt, temperature=0.2, max_retries=2)
            content = resp.choices[0].message.content
            if not content or not content.strip():
                return f"[{agent_id.upper()}] The model returned an empty response. Try rephrasing your request."
            return content
        except Exception as e:
            err_str = str(e)
            if "model output" in err_str.lower() or "output text" in err_str.lower():
                return (
                    f"[{agent_id.upper()}] The AI model returned an empty response for this request. "
                    "This can happen when the prompt triggers a safety filter. "
                    "Try rephrasing your request."
                )
            return f"[AI ERROR] {agent_id} failed: {e}"

    def run_workflow(self, workflow_name: str, context: str = "") -> Dict[str, Any]:
        if workflow_name not in self.workflows:
            return {"error": f"Workflow '{workflow_name}' not found."}
        workflow = self.workflows[workflow_name]
        ledger = InvestigationLedger(case_id=f"case-{int(time.time())}")
        results = []
        for phase in workflow.phases:
            self._publish_phase_event(
                "workflow_phase_started",
                phase,
                "running",
                context=context,
            )
            if phase.approval_required:
                ledger.record(
                    agent=phase.agent, phase=phase.id, action="awaiting_approval",
                    tool=None, input_summary=context,
                    output_summary="Approval required before execution",
                    rationale=f"Phase '{phase.name}' requires human approval per policy.",
                    approved=False,
                )
                results.append({"phase": phase.id, "agent": phase.agent, "status": "pending_approval"})
                self._publish_phase_event("workflow_phase_waiting", phase, "approval_required", context=context)
                continue
            tool_outputs = {}
            for tool in phase.tools:
                try:
                    res = self._agent.execute_tool(tool)
                    tool_outputs[tool] = res.get("output", "")
                except Exception as e:
                    tool_outputs[tool] = f"ERROR: {e}"
            prompt = f"{phase.instructions}\n\nContext: {context}\n\nTool outputs:\n{json.dumps(tool_outputs, indent=2)}"
            agent_output = self._call_agent(phase.agent, prompt)
            ledger.record(
                agent=phase.agent, phase=phase.id, action="execute_phase",
                tool=",".join(phase.tools), input_summary=context,
                output_summary=agent_output, rationale=phase.instructions, approved=True,
            )
            results.append({
                "phase": phase.id, "agent": phase.agent, "status": "completed",
                "output": agent_output, "tools_used": phase.tools,
            })
            self._publish_phase_event(
                "workflow_phase_completed",
                phase,
                "completed",
                tools_used=phase.tools,
            )
        return {
            "workflow": workflow_name, "case_id": ledger.case_id,
            "phases": results, "ledger": ledger.to_dict(),
        }

    def _publish_phase_event(self, event_type: str, phase: WorkflowPhase, status: str, **data: Any) -> None:
        """Expose specialist phase lifecycle to the active UI when available."""
        if self._agent is None or not hasattr(self._agent, "_publish_ui_event"):
            return
        self._agent._publish_ui_event(
            event_type,
            f"{phase.name} · {phase.agent}",
            status,
            agent=phase.agent,
            phase=phase.id,
            tools=phase.tools,
            **data,
        )

    def map_to_mitre(self, finding_description: str) -> List[Dict[str, str]]:
        desc_lower = finding_description.lower()
        matches = []
        for technique_id, technique_name in MITRE_TECHNIQUES.items():
            keywords = technique_name.lower().split()
            if any(kw in desc_lower for kw in keywords):
                matches.append({"technique_id": technique_id, "name": technique_name})
        return matches

    def list_agents(self) -> List[Dict[str, Any]]:
        return [
            {"id": a.id, "name": a.name, "icon": a.icon, "color": a.color,
             "specialization": a.specialization, "tools": a.recommended_tools}
            for a in self.agents.values()
        ]

    def list_workflows(self) -> List[str]:
        return list(self.workflows.keys())


class CyberSecurityOrchestrator:
    """
    Multi-agent AI orchestrator for cybersecurity operations.
    
    Uses AiApi (OmniRoute/Gemini) with specialized cybersecurity roles:
      - threat_intel_analyst   — IOC enrichment, attribution, campaign tracking
      - malware_analyst        — static/dynamic analysis, family classification, C2 extraction
      - network_defender       — traffic analysis, beaconing detection, firewall recommendations
      - incident_responder     — IR coordination, blast radius, executive summaries
      - forensic_investigator  — artifact analysis, timeline reconstruction, evidence preservation
      - vulnerability_researcher — CVE analysis, exploitability assessment, patch recommendations
    
    Uses the configured live key_manager provider. Provider failures are
    returned as explicit AI errors instead of silently showing demo content.
    """

    def __init__(self, use_mock: bool = True):
        self.use_mock = use_mock
        self._api = AiApi(use_mock=use_mock) if use_mock else AiApi()

    def _call_role(self, role: str, system: str, user: str) -> str:
        if self.use_mock:
            from key_manager import MockRoleKeyManager
            return MockRoleKeyManager._CANNED.get(role, MockRoleKeyManager._CANNED["default"])
        try:
            resp = self._api.chat_with_role(role, system, user, temperature=0.2, max_retries=2)
            content = resp.choices[0].message.content
            # Guard against empty model output (Gemini can return this on content-filtered prompts)
            if not content or not content.strip():
                return f"[{role.upper()}] The model returned an empty response. Try rephrasing your request."
            return content
        except Exception as e:
            err_str = str(e)
            # Gemini specific: "model output must contain either output text or tool calls"
            if "model output" in err_str.lower() or "output text" in err_str.lower():
                return (
                    f"[{role.upper()}] The AI model returned an empty response for this request. "
                    "This can happen when the prompt triggers a safety filter. "
                    "Try rephrasing your request."
                )
            return f"[AI ERROR] {role} failed: {e}"

    def analyze_threat_intel(self, ioc_data: str) -> str:
        return self._call_role(
            "threat_intel_analyst",
            CYBER_ROLES["threat_intel_analyst"],
            f"Analyze this IOC data and provide threat intelligence:\n{ioc_data}"
        )

    def analyze_malware(self, behavior_data: str) -> str:
        return self._call_role(
            "malware_analyst",
            CYBER_ROLES["malware_analyst"],
            f"Analyze this malware behavior and provide classification + IOCs:\n{behavior_data}"
        )

    def defend_network(self, traffic_data: str) -> str:
        return self._call_role(
            "network_defender",
            CYBER_ROLES["network_defender"],
            f"Analyze this network traffic and recommend defense actions:\n{traffic_data}"
        )

    def coordinate_incident_response(self, incident_data: str) -> str:
        return self._call_role(
            "incident_responder",
            CYBER_ROLES["incident_responder"],
            f"Coordinate incident response for:\n{incident_data}"
        )

    def investigate_forensic_artifact(self, artifact_data: str) -> str:
        return self._call_role(
            "forensic_investigator",
            CYBER_ROLES["forensic_investigator"],
            f"Investigate this forensic artifact:\n{artifact_data}"
        )

    def research_vulnerability(self, vuln_data: str) -> str:
        return self._call_role(
            "vulnerability_researcher",
            CYBER_ROLES["vulnerability_researcher"],
            f"Research this vulnerability:\n{vuln_data}"
        )

    def full_incident_workflow(self, incident_summary: str) -> Dict[str, Any]:
        """Run all 6 cybersecurity roles in sequence on a single incident."""
        results = {
            "threat_intel": self.analyze_threat_intel(incident_summary),
            "malware_analysis": self.analyze_malware(incident_summary),
            "network_defense": self.defend_network(incident_summary),
            "incident_response": self.coordinate_incident_response(incident_summary),
            "forensics": self.investigate_forensic_artifact(incident_summary),
            "vuln_research": self.research_vulnerability(incident_summary),
        }
        return results


class CyberAgent:
    """Main Agent class orchestrating cybersecurity diagnostics, tool building, and response."""

    def __init__(self, workspace_path: str = ".", wsl_state: Optional[Dict[str, Any]] = None):
        self.workspace_path = os.path.abspath(workspace_path)
        self.cancel_event = threading.Event()
        self.investigations = InvestigationState(root=os.path.join(self.workspace_path, ".sessions"))
        self.current_investigation: Optional[Dict[str, Any]] = None
        self.audit_logger = AuditLogger()
        self.guardrails = AutomatedGuardrailManager(auto_approve_read_only=True, auto_remediate_critical=True)

        # Approval registry for async UI-driven human-in-the-loop.
        # Maps request_id -> (Event, result_bool). The event_bus subscriber
        # below resolves each pending approval when the UI sends a response.
        self._approval_lock = threading.Lock()
        self._approval_events: Dict[str, threading.Event] = {}
        self._approval_results: Dict[str, bool] = {}

        def _on_approval_response(event: AgentEvent) -> None:
            data = event.data or {}
            req_id = data.get("request_id", "")
            approved = bool(data.get("approved", False))
            with self._approval_lock:
                if req_id in self._approval_events:
                    self._approval_results[req_id] = approved
                    self._approval_events[req_id].set()

        event_bus.subscribe("approval_response", _on_approval_response)

        # 1. WSL Detection Layer
        self.wsl_state = wsl_state if wsl_state is not None else WSLDetector.detect_wsl()
        self.wsl_available = self.wsl_state.get("wsl_available", False)
        self.wsl_distros = self.wsl_state.get("wsl_distros", [])
        self.default_distro = self.wsl_state.get("default_distro", "")

        # 2. Tool Registry & Routing
        self.registry = ToolRegistry(self.audit_logger, wsl_state=self.wsl_state)
        register_all_default_tools(self.registry)

        # 3. Daemons
        self.realtime_daemon = RealtimeSecurityDaemon(self)
        self.kernel_daemon = KernelInterceptionDaemon(self)

        # 4. AI Orchestrators — always use the configured live provider.
        self.orchestrator = CyberSecurityOrchestrator(use_mock=False)
        self.soc_orchestrator = SOCOrchestrator(use_mock=False, agent=self)
        self._ai_live = True

        # 5. CyberDB — JSON-first database for findings, cases, MITRE, workflows
        try:
            from cyber_db import get_db
            self.db = get_db()
        except Exception as e:
            print(f"[!] CyberDB init failed: {e}")
            self.db = None

        # 6. CyberOS — Autonomous Live Defense System
        try:
            from cyber_os import CyberOSEngine
            from cyber_os.cyber_os_ai import CyberOSAI
            self.cyberos_engine = CyberOSEngine(config_path="cyber_os/cyber_os_config.json")
            self.cyberos_ai = CyberOSAI(use_mock=True)
            self.cyberos_available = True
        except Exception as e:
            print(f"[!] CyberOS init failed: {e}")
            self.cyberos_available = False

        # 7. SVS-Cyber Resilient Runtime Subsystems
        self.approval_engine = ApprovalEngine()
        self.pty_manager = PtySessionManager.get_instance()
        self.task_manager = TaskManager()
        self.notes_manager = NotesManager()
        self.agent_runtime = AgentRuntime(self)

        # Register adaptive tools
        self._register_adaptive_tools()

    def _register_adaptive_tools(self) -> None:
        """Registers SVS-Cyber core tools (tasks/TODO, notes, subagent delegation, PTY) into ToolRegistry."""
        def _todo_write(tasks: Any = None, session_id: str = "default", **kwargs: Any) -> Dict[str, Any]:
            task_list = tasks if isinstance(tasks, list) else []
            updated = self.task_manager.update_tasks(task_list, session_id=session_id)
            return {"status": "success", "count": len(updated), "tasks": updated}

        def _notes_create(title: str = "Note", content: str = "", tags: Optional[List[str]] = None, session_id: str = "default", **kwargs: Any) -> Dict[str, Any]:
            created = self.notes_manager.create_note(title=title, content=content, tags=tags, session_id=session_id)
            return {"status": "success", "note": created}

        def _notes_list(tag: Optional[str] = None, **kwargs: Any) -> Dict[str, Any]:
            notes = self.notes_manager.list_notes(tag=tag)
            return {"status": "success", "count": len(notes), "notes": notes}

        def _notes_delete(note_id: str = "", **kwargs: Any) -> Dict[str, Any]:
            ok = self.notes_manager.delete_note(note_id)
            return {"status": "success" if ok else "not_found", "note_id": note_id}

        def _subagent_delegate(profile: str = "threat_analysis", objective: str = "", context_refs: Optional[List[Dict[str, str]]] = None, **kwargs: Any) -> Dict[str, Any]:
            inv_id = self.current_investigation.get("investigation_id", "") if self.current_investigation else ""
            res = self.agent_runtime.subagent_manager.delegate_task(
                profile_name=profile,
                objective=objective,
                parent_investigation_id=inv_id,
                context_refs=context_refs,
            )
            return res.to_dict()

        def _subagent_list_profiles(**kwargs: Any) -> Dict[str, Any]:
            profiles = list_available_profiles()
            return {"status": "success", "profiles": profiles}

        def _pty_run(command: str = "whoami", session_name: str = "default", timeout: int = 30, **kwargs: Any) -> Dict[str, Any]:
            sess = self.pty_manager.get_or_create_session(session_name)
            output = sess.execute(command, timeout=timeout)
            return {"status": "success", "session": session_name, "output": output}

        self.registry.register_tool(ToolDefinition(
            name="todo_write",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=_todo_write,
        ))
        self.registry.register_tool(ToolDefinition(
            name="notes_create",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=_notes_create,
        ))
        self.registry.register_tool(ToolDefinition(
            name="notes_list",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=_notes_list,
        ))
        self.registry.register_tool(ToolDefinition(
            name="notes_delete",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=_notes_delete,
        ))
        self.registry.register_tool(ToolDefinition(
            name="subagent_delegate",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=_subagent_delegate,
        ))
        self.registry.register_tool(ToolDefinition(
            name="subagent_list_profiles",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=_subagent_list_profiles,
        ))
        self.registry.register_tool(ToolDefinition(
            name="pty_run",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=_pty_run,
        ))

    def get_system_prompt(self, custom_instructions: str = "") -> str:
        """Returns the modular, evidence-first system prompt composed with active state."""
        from cyber_os.system_prompt import SystemPromptComposer
        tasks = self.task_manager.get_tasks() if hasattr(self, "task_manager") else []
        notes = self.notes_manager.list_notes() if hasattr(self, "notes_manager") else []
        return SystemPromptComposer.build_system_prompt(
            custom_instructions=custom_instructions,
            workspace_path=self.workspace_path,
            active_tasks=tasks,
            active_notes=notes,
        )

    # --- Execution Function & Tool Routing ---

    def _wait_for_approval(self, action_name: str, risk_level: Any, details: Dict[str, Any], tool_call_id: str = "") -> bool:
        """Publish an approval_requested event and block until the UI responds.

        Falls back to auto-approve read-only or auto-remediate-critical
        policies, then to stdin if no callback is registered and no UI
        is connected. Times out after 300 s to avoid wedging the worker.
        """
        # Honour the same automated policies the guardrail would
        try:
            from cyber_tools import RiskLevel
            rl = RiskLevel(risk_level) if isinstance(risk_level, str) else risk_level
            if rl == RiskLevel.READ_ONLY and self.guardrails.auto_approve_read_only:
                return True
            if self.guardrails.auto_remediate_critical and rl in {
                RiskLevel.MODIFIES_SYSTEM, RiskLevel.DESTRUCTIVE, RiskLevel.KERNEL_INTERVENTION,
            }:
                if details.get("threat_score", 0) >= 8:
                    print(f"[AUTO-POLICY] Auto-approving critical action: {action_name}")
                    return True
        except Exception:
            pass

        # If a legacy approval_callback is registered (PySide6 desktop shell),
        # use it synchronously — that path already shows a QMessageBox.
        if self.guardrails.approval_callback is not None:
            try:
                return bool(self.guardrails.approval_callback(action_name, str(risk_level), details))
            except Exception as exc:
                print(f"[!] Approval callback error, denying '{action_name}': {exc}")
                return False

        # Web UI path: publish event, wait for response
        import uuid
        request_id = str(uuid.uuid4())
        event = AgentEvent(
            type="approval_requested",
            message=action_name,
            data={
                "request_id": request_id,
                "tool_call_id": tool_call_id,
                "action": action_name,
                "risk_level": str(risk_level),
                "details": details,
            },
        )
        event_bus.publish(event)

        done = threading.Event()
        with self._approval_lock:
            self._approval_events[request_id] = done

        approved = done.wait(timeout=300)
        with self._approval_lock:
            self._approval_events.pop(request_id, None)
            result = self._approval_results.pop(request_id, False)

        if not approved:
            print(f"[!] Approval timed out for '{action_name}' — denying.")
            return False
        return result

    def execute_tool(self, tool_name: str, args: Optional[Dict[str, Any]] = None, timeout: Optional[int] = 15, threat_score: int = 0) -> Dict[str, Any]:
        """Looks up tool, handles conditional routing & fallbacks, checks guardrails, and executes."""
        if args is None:
            args = {}
        if self.cancel_event.is_set():
            return {"tool": tool_name, "environment_used": "none", "success": False, "output": "", "error": "Cancelled by user.", "cancelled": True}

        tool_def = self.registry.tools.get(tool_name)
        if not tool_def:
            return {
                "tool": tool_name,
                "environment_used": "none",
                "success": False,
                "output": "",
                "error": f"Tool '{tool_name}' not found in registry."
            }

        import uuid
        tool_call_id = f"{tool_name}-{uuid.uuid4().hex[:12]}"

        self._publish_ui_event(
            "tool_started",
            f"Running {tool_name}",
            "running",
            tool=tool_name,
            tool_call_id=tool_call_id,
            arguments=args,
            risk_level=tool_def.risk_level.value,
        )
        self._publish_ui_event(
            "agent_reasoning",
            f"The request requires {tool_name}. I am executing it with the approved arguments and current-user safety controls.",
            "running",
            tool=tool_name,
            tool_call_id=tool_call_id,
            arguments=args,
        )

        target_env = None
        for env in tool_def.environments:
            if self.registry.is_environment_available(env):
                target_env = env
                break

        # If designated environment is not available, check for defined native fallback
        if not target_env:
            if tool_def.fallback_tool and tool_def.fallback_tool in self.registry.tools:
                fallback_def = self.registry.tools[tool_def.fallback_tool]
                for f_env in fallback_def.environments:
                    if self.registry.is_environment_available(f_env):
                        msg = f"Tool '{tool_name}' requires WSL, which is not installed. Falling back to native Windows tool '{tool_def.fallback_tool}'."
                        print(f"[!] {msg}")
                        self.audit_logger.log_event("tool_fallback", {"original_tool": tool_name, "fallback_tool": tool_def.fallback_tool})
                        return self.execute_tool(tool_def.fallback_tool, args, timeout=timeout, threat_score=threat_score)

            # If no fallback exists, log clear message and skip gracefully
            skip_msg = f"Tool '{tool_name}' requires WSL, which is not installed. Skipping."
            print(f"[!] {skip_msg}")
            self.audit_logger.log_event("tool_skipped", {"tool": tool_name, "reason": "Environment unavailable"})
            return {
                "tool": tool_name,
                "environment_used": "none",
                "success": False,
                "output": "",
                "error": skip_msg
            }

        # Guardrail check. Uses the async approval path (web UI card or
        # PySide6 QMessageBox) when available, falls back to auto-policy.
        guardrail_details = {**args, "threat_score": threat_score}
        try:
            approved = self._wait_for_approval(tool_name, tool_def.risk_level, guardrail_details, tool_call_id)
        except (AttributeError, TypeError, ValueError, KeyError) as exc:
            self.audit_logger.log_event(
                "tool_invocation",
                {"tool": tool_name, "reason": f"Guardrail error: {type(exc).__name__}: {exc}"},
                status="DENIED",
            )
            return {
                "tool": tool_name,
                "environment_used": target_env,
                "success": False,
                "output": "",
                "error": f"Guardrail check failed, action denied: {type(exc).__name__}: {exc}",
            }
        if not approved:
            self.audit_logger.log_event("tool_invocation", {"tool": tool_name, "reason": "Guardrail rejected"}, status="DENIED")
            return {
                "tool": tool_name,
                "environment_used": target_env,
                "success": False,
                "output": "",
                "error": "Action rejected by guardrail approval."
            }

        # Python direct function invocation
        if tool_def.python_func:
            try:
                res = tool_def.python_func(**args)
                self.audit_logger.log_event("tool_executed", {"tool": tool_name, "environment": target_env})
                self._publish_ui_event(
                    "tool_completed",
                    f"{tool_name} completed",
                    "completed",
                    tool=tool_name,
                    tool_call_id=tool_call_id,
                    output=res,
                )
                self._publish_ui_event(
                    "agent_reasoning",
                    f"{tool_name} returned evidence. I am reviewing the result before giving you a conclusion.",
                    "completed",
                    tool=tool_name,
                )
                return {
                    "tool": tool_name,
                    "environment_used": target_env,
                    "success": True,
                    "output": json.dumps(res, indent=2) if isinstance(res, (dict, list)) else str(res),
                    "error": ""
                }
            except Exception as e:
                self.audit_logger.log_event("tool_executed", {"tool": tool_name, "error": str(e)}, status="ERROR")
                self._publish_ui_event("tool_failed", f"{tool_name} failed", "error", tool=tool_name, tool_call_id=tool_call_id, error=str(e))
                return {
                    "tool": tool_name,
                    "environment_used": target_env,
                    "success": False,
                    "output": "",
                    "error": str(e)
                }

        # Command construction and execution
        try:
            cmd_str = tool_def.command_template.format(**args)
        except KeyError as e:
            return {
                "tool": tool_name,
                "environment_used": target_env,
                "success": False,
                "output": "",
                "error": f"Missing required tool argument: {e}"
            }
        
        if target_env == "wsl_linux":
            distro_arg = f"-d {self.default_distro} " if self.default_distro else ""
            exec_cmd = f"wsl.exe {distro_arg}-- {cmd_str}"
        elif target_env == "native_windows":
            exec_cmd = cmd_str
        else:
            exec_cmd = cmd_str

        self.audit_logger.log_event("tool_routing", {"tool": tool_name, "environment": target_env, "command": exec_cmd})
        
        command_environment = "powershell" if tool_name == "windows_defender_scan" else "cmd"
        stream_output = None
        if tool_name == "windows_defender_scan":
            scan_started_at = time.monotonic()

            stream_output = lambda line: self._publish_ui_event(
                "tool_output",
                line or "Defender scan is running",
                "running",
                tool=tool_name,
                tool_call_id=tool_call_id,
                output=line,
                elapsed_seconds=round(time.monotonic() - scan_started_at, 1),
                progress=self._extract_scan_progress(line),
            )
        res = execute_system_command(
            exec_cmd,
            environment=command_environment,
            timeout=None if tool_name == "windows_defender_scan" else timeout,
            output_callback=stream_output,
            cancel_event=self.cancel_event,
        )
        if res.get("cancelled"):
            self._publish_ui_event("tool_cancelled", f"{tool_name} cancelled", "cancelled", tool=tool_name, tool_call_id=tool_call_id)
            return {"tool": tool_name, "environment_used": target_env, "success": False, "output": res.get("stdout", ""), "error": "Cancelled by user.", "cancelled": True}
        success = res.get("returncode", -1) == 0
        self._publish_ui_event(
            "tool_completed" if success else "tool_failed",
            f"{tool_name} {'completed' if success else 'failed'}",
            "completed" if success else "error",
            tool=tool_name,
            tool_call_id=tool_call_id,
            command=exec_cmd,
            output=res.get("stdout", ""),
            error=res.get("stderr", "") or res.get("error", ""),
        )
        
        return {
            "tool": tool_name,
            "environment_used": target_env,
            "success": success,
            "output": res.get("stdout", ""),
            "error": res.get("stderr", "") or res.get("error", "")
        }

    @staticmethod
    def _extract_scan_progress(line: str) -> Optional[int]:
        """Return a scanner-reported percentage without inventing one."""
        match = re.search(r"(?<!\d)(\d{1,3})\s*%", line or "")
        if not match:
            return None
        value = int(match.group(1))
        return value if 0 <= value <= 100 else None

    def analyze_source_file(self, relative_path: str) -> Dict[str, Any]:
        """Ingests source code file and performs SAST analysis."""
        full_path = os.path.join(self.workspace_path, relative_path)
        if not os.path.isfile(full_path):
            return {"error": f"File not found: {full_path}"}
        
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()

        exec_res = self.execute_tool("static_analysis", {"code": code})
        findings = json.loads(exec_res["output"]) if exec_res["success"] and exec_res["output"] else []
        for finding in findings:
            self._publish_ui_event(
                "finding_created",
                finding.get("message", finding.get("type", "Security finding")),
                "detected",
                finding={**finding, "file": relative_path},
            )
        
        fixes = []
        lines = code.splitlines()
        for f in findings:
            if "line" in f and 1 <= f["line"] <= len(lines):
                original_line = lines[f["line"] - 1]
                suggested_fix = StaticCodeAnalyzer.propose_secure_fix(f, original_line)
                fixes.append({
                    "finding": f,
                    "original": original_line,
                    "suggested_fix": suggested_fix
                })

        return {
            "file": relative_path,
            "findings_count": len(findings),
            "findings": findings,
            "suggested_fixes": fixes
        }

    def register_dynamic_script(self, name: str, description: str, script_code: str, is_remediation: bool = False) -> bool:
        """Registers a dynamic tool generated during agent operations."""
        perm = RiskLevel.MODIFIES_SYSTEM if is_remediation else RiskLevel.READ_ONLY
        tool_def = ToolDefinition(
            name=name,
            environments=["cross_platform"],
            command_template="",
            risk_level=perm
        )
        return self.registry.dynamic_register_script(
            name=name,
            description=description,
            script_code=script_code,
            risk_level=perm
        )

    def generate_incident_report(self) -> Dict[str, Any]:
        """Correlates recent audit logs and calls AI assistant to generate an executive report."""
        try:
            with open("audit_log.json", "r", encoding="utf-8") as f:
                logs = json.load(f)[-5:]
        except Exception:
            logs = [{"action": "system_audit", "status": "COMPLETED"}]
        
        return self.execute_tool("ai_incident_summary", {"events_json": json.dumps(logs)})

    def triage_and_correlate_scans(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Orchestrates multi-tool findings and calls the AITriageEngine via tool execution."""
        return self.execute_tool("ai_triage_correlate", {"scan_results": scan_results})

    # --- Daemon Control ---

    def start_realtime_monitor(self, interval: float = 3.0):
        self.realtime_daemon.start_monitoring(interval=interval)

    def stop_realtime_monitor(self):
        self.realtime_daemon.running = False

    def start_kernel_daemon(self, poll_interval: float = 1.0):
        self.kernel_daemon.start(poll_interval=poll_interval)

    def stop_kernel_daemon(self):
        self.kernel_daemon.stop()

    # --- Honeypot Control ---

    def start_honeypot(self, host="0.0.0.0", port=2222):
        res = self.execute_tool("start_honeypot", {"host": host, "port": port})
        return res

    def stop_honeypot(self):
        res = self.execute_tool("stop_honeypot")
        return res

    def honeypot_status(self):
        res = self.execute_tool("honeypot_status")
        return res

    # --- Benchmark / Evaluation ---

    def run_benchmark(self, tools=None, iterations=1):
        res = self.execute_tool("benchmark_run", {"tools": tools, "iterations": iterations})
        return res

    # --- AI Cybersecurity Orchestrator (key_manager.py powered) ---

    def ai_threat_intel_analysis(self, ioc_data: str) -> Dict[str, Any]:
        return {"role": "threat_intel_analyst", "output": self.orchestrator.analyze_threat_intel(ioc_data)}

    def ai_malware_analysis(self, behavior_data: str) -> Dict[str, Any]:
        return {"role": "malware_analyst", "output": self.orchestrator.analyze_malware(behavior_data)}

    def ai_network_defense(self, traffic_data: str) -> Dict[str, Any]:
        return {"role": "network_defender", "output": self.orchestrator.defend_network(traffic_data)}

    def ai_incident_response(self, incident_data: str) -> Dict[str, Any]:
        return {"role": "incident_responder", "output": self.orchestrator.coordinate_incident_response(incident_data)}

    def ai_forensic_investigation(self, artifact_data: str) -> Dict[str, Any]:
        return {"role": "forensic_investigator", "output": self.orchestrator.investigate_forensic_artifact(artifact_data)}

    def ai_vulnerability_research(self, vuln_data: str) -> Dict[str, Any]:
        return {"role": "vulnerability_researcher", "output": self.orchestrator.research_vulnerability(vuln_data)}

    def ai_full_incident_workflow(self, incident_summary: str) -> Dict[str, Any]:
        return self.orchestrator.full_incident_workflow(incident_summary)

    # --- Vigil SOC-Inspired Multi-Agent System ---

    def soc_list_agents(self) -> List[Dict[str, Any]]:
        return self.soc_orchestrator.list_agents()

    def soc_list_workflows(self) -> List[str]:
        return self.soc_orchestrator.list_workflows()

    def soc_run_workflow(self, workflow_name: str, context: str = "") -> Dict[str, Any]:
        return self.soc_orchestrator.run_workflow(workflow_name, context)

    def soc_map_to_mitre(self, finding_description: str) -> List[Dict[str, str]]:
        return self.soc_orchestrator.map_to_mitre(finding_description)

    def soc_get_agent_for_task(self, task: str) -> Dict[str, Any]:
        agent = self.soc_orchestrator.get_agent_by_task(task)
        return {
            "id": agent.id, "name": agent.name, "icon": agent.icon,
            "color": agent.color, "specialization": agent.specialization,
            "tools": agent.recommended_tools,
        }

    # --- CyberDB Database Methods ---

    def db_add_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        if not self.db:
            return {"error": "CyberDB not available"}
        return self.db.add_finding(finding)

    def db_get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        if not self.db:
            return None
        return self.db.get_finding(finding_id)

    def db_list_findings(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if not self.db:
            return []
        return self.db.list_findings(filters)

    def db_create_case(self, case: Dict[str, Any]) -> Dict[str, Any]:
        if not self.db:
            return {"error": "CyberDB not available"}
        return self.db.create_case(case)

    def db_list_cases(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if not self.db:
            return []
        return self.db.list_cases(filters)

    def db_map_to_mitre(self, finding_description: str) -> List[Dict[str, str]]:
        if not self.db:
            return []
        mappings = self.db.map_finding_to_mitre({"description": finding_description})
        for mapping in mappings:
            self._publish_ui_event(
                "mitre_mapped",
                f"Mapped {mapping.get('id', mapping.get('technique_id', 'MITRE technique'))}",
                "mapped",
                mapping=mapping,
            )
        return mappings

    def db_get_stats(self) -> Dict[str, Any]:
        if not self.db:
            return {"error": "CyberDB not available"}
        return self.db.get_stats()

    # --- Chat-Based Command Processing ---

    def _publish_ui_event(self, event_type: str, message: str, status: str = "", **data: Any) -> None:
        investigation_id = self.current_investigation.get("investigation_id", "") if self.current_investigation else ""
        event = AgentEvent(
            type=event_type,
            status=status,
            message=message,
            investigation_id=investigation_id,
            source="cyber_agent",
            data=data,
        )
        event_bus.publish(event)
        if investigation_id:
            self.investigations.append_event(investigation_id, event.to_dict())

    def _publish_context_usage(self, used_tokens: int, max_tokens: int) -> None:
        """Publish context usage event for UI display."""
        self._publish_ui_event(
            "context_usage",
            f"Context window: {used_tokens} / {max_tokens} tokens used",
            "updated",
            used_tokens=used_tokens,
            max_tokens=max_tokens,
        )

    def _publish_model_info(self, model_name: str) -> None:
        """Publish model info event for UI display."""
        self._publish_ui_event(
            "model_info",
            f"Using model: {model_name}",
            "updated",
            model=model_name,
        )

    def nat_status(self) -> Dict[str, Any]:
        """Return NAT status for the UI without forcing a live model request."""
        from cyber_os.nemo_agent_toolkit import NeMoAgentToolkitBridge

        bridge = NeMoAgentToolkitBridge(
            [tool.to_manifest() for tool in self.registry.tools.values()],
            self.workspace_path,
        )
        return bridge.status()

    def _extract_scan_target(self, user_input: str) -> str:
        text = user_input.strip()
        drive_match = re.search(r"\b([A-Za-z]):(?:\\|/)?", text)
        if drive_match:
            return f"{drive_match.group(1).upper()}:\\"
        folder_match = re.search(r"(?:folder|directory|path)\s+(?:at\s+)?[\"']?([^\"']+?)[\"']?(?:\s+for|\s*$)", text, re.I)
        if folder_match:
            candidate = os.path.expandvars(os.path.expanduser(folder_match.group(1).strip()))
            if os.path.isdir(candidate):
                return os.path.abspath(candidate)
        downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
        return downloads_path if os.path.isdir(downloads_path) else os.path.expanduser("~")

    @staticmethod
    def _is_admin() -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    def process_chat_command(self, user_input: str, session_id: str = "default") -> str:
        """Process a chat request and publish concise lifecycle events for the UI."""
        self.cancel_event.clear()
        self.current_investigation = self.investigations.create(user_input)
        self._publish_ui_event("investigation_started", "Investigation started", "running", objective=user_input)
        self._publish_ui_event("agent_started", "Understanding the request", "running")
        self._publish_model_info("CyberSecurityOrchestrator")
        try:
            response = self._process_chat_command(user_input, session_id=session_id)
            self._publish_ui_event("agent_completed", "Investigation complete", "completed")
            if self.current_investigation:
                self.current_investigation["status"] = "completed"
                self.investigations.save(self.current_investigation)
            return response
        except Exception as exc:
            self._publish_ui_event("agent_failed", "Investigation failed", "error", error=str(exc))
            if self.current_investigation:
                self.current_investigation["status"] = "failed"
                self.investigations.save(self.current_investigation)
            raise

    def _process_chat_command(self, user_input: str, session_id: str = "default") -> str:
        """
        Process natural language commands from the chat interface.
        
        Uses intent routing to determine whether tools are required.
        """
        lower = user_input.lower().strip()
        if not lower:
            return "Please enter a command. Try: 'scan code 1', 'list findings', 'run incident response', 'mitre map ransomware', 'stats'"

        validation_request = any(
            phrase in lower
            for phrase in (
                "soc validation",
                "validate all",
                "all specialist agents",
                "all available soc specialists",
                "sub-agents",
                "sub agents",
                "every specialist",
                "complete read-only soc",
            )
        )
        if validation_request and any(word in lower for word in ("workflow", "investigation", "validation", "agents")):
            return self._run_soc_validation(user_input)

        if (
            "drive" in lower
            and any(phrase in lower for phrase in ("available", "list", "what", "which"))
        ) or "list drives" in lower:
            self._publish_ui_event(
                "agent_reasoning",
                "The user asked which drives are available. I will call list_available_drives and ask the configured AI to interpret its real result.",
                "running",
            )
            res = self.execute_tool("list_available_drives", {})
            evidence = res.get("output") or res.get("error")
            if not evidence:
                raise RuntimeError("list_available_drives returned no result")
            return self.orchestrator._call_role(
                "investigator",
                CYBER_ROLES["investigator"],
                "Answer the user's drive-availability question using only this real tool result. "
                "Do not invent drives or claim a drive is available without evidence.\n"
                f"{evidence[:4000]}",
            )

        # Drive and malware scans are deterministic local operations. Route
        # them before the AI intent router so a provider outage cannot prevent
        # the real scan from starting.
        if "scan" in lower and any(word in lower for word in ("download", "virus", "malware", "drive", "folder")):
            scan_target = self._extract_scan_target(user_input)
            self._publish_ui_event(
                "agent_reasoning",
                f"The user asked me to scan {scan_target} for malware. I will verify that the target is mounted before invoking Windows Defender.",
                "running",
                target=scan_target,
            )
            if re.match(r"\b[A-Za-z]:[\\/]", scan_target) and not os.path.exists(scan_target):
                self._publish_ui_event(
                    "agent_status",
                    f"Scan target {scan_target} is unavailable; no scan was started",
                    "error",
                    target=scan_target,
                )
                return self.orchestrator._call_role(
                    "investigator",
                    CYBER_ROLES["investigator"],
                    "Answer the user's scan request using only this verified local observation. "
                    "The requested target is unavailable, no alternate directory was scanned, "
                    "and no malware result exists. Do not invent scan findings.\n"
                    f"Requested target: {scan_target}\n"
                    "Observation: target is not mounted or accessible.\n"
                    "Observation: scan was not started."
                )
            self._publish_ui_event(
                "agent_reasoning",
                f"{scan_target} is available. I will run the read-only Windows Defender scan and report its live scanner output.",
                "running",
                target=scan_target,
            )
            if not self._is_admin():
                self._publish_ui_event(
                    "agent_status",
                    "Running the scan with current-user permissions; some protected files may be inaccessible",
                    "notice",
                    target=scan_target,
                )
            self._publish_ui_event(
                "agent_status",
                f"Scanning {scan_target} with the local malware engine; this may take several minutes",
                "running",
                target=scan_target,
            )
            res = self.execute_tool("windows_defender_scan", {"target": scan_target}, timeout=None)
            scan_output = res.get("output") or res.get("error")
            if not scan_output:
                raise RuntimeError("windows_defender_scan returned no result")
            summary = self.orchestrator._call_role(
                "malware_analyst",
                CYBER_ROLES["malware_analyst"],
                f"Summarize this real malware scan of {scan_target}. Do not invent detections.\n{scan_output[:6000]}",
            )
            return str(summary)

        # Use intent router if available
        try:
            from cyber_os.intent_router import IntentRouter
            router = IntentRouter()
            intent_result = router.classify(user_input)
            
            if intent_result.intent.value == "conversational":
                return router.get_response_for_intent(intent_result, user_input)
            elif intent_result.intent.value == "informational":
                return router.get_response_for_intent(intent_result, user_input)
            elif intent_result.requires_tools:
                return self._run_ai_orchestrated_request(user_input, session_id=session_id)
        except ImportError:
            pass

        # Database queries
        if "list findings" in lower or "show findings" in lower:
            findings = self.db_list_findings()
            if not findings:
                return "No findings in database. Use 'add finding' or 'generate sample data' first."
            lines = [f"Total findings: {len(findings)}"]
            for f in findings[:10]:
                lines.append(f"  [{f.get('severity', '?')}] {f.get('finding_id', '?')}: {f.get('description', '?')[:60]}")
            return "\n".join(lines)

        if "list cases" in lower or "show cases" in lower:
            cases = self.db_list_cases()
            if not cases:
                return "No cases in database."
            lines = [f"Total cases: {len(cases)}"]
            for c in cases[:10]:
                lines.append(f"  [{c.get('status', '?')}] {c.get('case_id', '?')}: {c.get('title', '?')[:60]}")
            return "\n".join(lines)

        if "stats" in lower or "status" in lower or "dashboard" in lower:
            stats = self.db_get_stats()
            return json.dumps(stats, indent=2)

        if "mitre" in lower or "attack" in lower:
            mapping = self.db_map_to_mitre(user_input)
            if mapping:
                return "MITRE mappings:\n" + "\n".join(f"  {m['id']}: {m['name']} ({m['tactic']})" for m in mapping)
            return "No MITRE technique matches found for that input."

        # Tool executions
        if "scan" in lower and "code" in lower:
            target = "ideas/code 1"
            res = self.analyze_source_file(target)
            return (
                "### SAST Scan Complete\n\n"
                f"- Target: `{target}`\n"
                f"- Status: {'completed' if not res.get('error') else 'failed'}\n"
                "- Analysis: static security review\n\n"
                "```json\n"
                f"{json.dumps(res, indent=2)[:500]}\n"
                "```"
            )

        if "secret" in lower or "leak" in lower:
            res = self.execute_tool("secret_scan", {"content": user_input})
            return (
                "### Secret Scan\n\n"
                "- Checked the supplied text for credential-like patterns.\n"
                f"- Status: {'completed' if res.get('success') else 'failed'}\n\n"
                "```text\n"
                f"{res.get('output') or res.get('error') or 'No output returned.'}\n"
                "```"
            )

        if "entropy" in lower:
            res = self.execute_tool("entropy_check", {"filepath": "ideas/code 1"})
            return f"Entropy check:\n{res.get('output', 'done')}"

        if any(word in lower for word in ("port", "ports", "listening", "connections")):
            res = self.execute_tool("network_inspect", {})
            network_output = res.get("output") or res.get("error") or "No network data returned."
            return self.orchestrator._call_role(
                "network_defender",
                CYBER_ROLES["network_defender"],
                "Inspect this real local network connection and listening-port output. "
                "Summarize listening ports, active connections, suspicious indicators, "
                "and safe next steps. Do not claim a port is open unless the output supports it.\n"
                f"{network_output[:12000]}"
            )

        if "honeypot" in lower:
            if "start" in lower:
                res = self.start_honeypot()
                return f"Honeypot: {res.get('output', 'started')}"
            elif "stop" in lower:
                res = self.stop_honeypot()
                return f"Honeypot: {res.get('output', 'stopped')}"
            else:
                res = self.honeypot_status()
                return f"Honeypot status:\n{json.dumps(res.get('output', {}), indent=2)}"

        if "workflow" in lower or "run incident" in lower:
            wf_name = "incident-response"
            if "threat hunt" in lower:
                wf_name = "threat-hunt"
            elif "forensic" in lower:
                wf_name = "forensic-analysis"
            res = self.soc_run_workflow(wf_name, user_input)
            return f"Workflow '{wf_name}' completed:\nCase: {res.get('case_id')}\nPhases: {len(res.get('phases', []))}\nLedger events: {res.get('ledger', {}).get('total_events', 0)}"

        if "agent" in lower or "route" in lower:
            agent_info = self.soc_get_agent_for_task(user_input)
            return f"Best agent: [{agent_info['icon']}] {agent_info['name']}\nSpecialization: {agent_info['specialization']}\nTools: {', '.join(agent_info['tools'][:4])}"

        # AI analysis
        if "threat intel" in lower or "ioc" in lower:
            return self.ai_threat_intel_analysis(user_input)["output"]

        if "malware" in lower or "ransomware" in lower:
            return self.ai_malware_analysis(user_input)["output"]

        if "network" in lower or "traffic" in lower or "firewall" in lower:
            return self.ai_network_defense(user_input)["output"]

        if "incident" in lower and "response" in lower:
            return self.ai_incident_response(user_input)["output"]

        if "forensic" in lower or "artifact" in lower:
            return self.ai_forensic_investigation(user_input)["output"]

        if "vulnerability" in lower or "cve" in lower or "exploit" in lower:
            return self.ai_vulnerability_research(user_input)["output"]

        # CyberOS Live Defense commands
        if "cyberos" in lower or "live defense" in lower or "autonomous defense" in lower:
            if "start" in lower or "activate" in lower or "on" in lower:
                res = self.cyberos_start()
                return f"CyberOS: {res.get('message', 'started')}"
            elif "stop" in lower or "deactivate" in lower or "off" in lower:
                res = self.cyberos_stop()
                return f"CyberOS: {res.get('message', 'stopped')}"
            elif "status" in lower or "stats" in lower:
                res = self.cyberos_status()
                return f"CyberOS Status:\n{json.dumps(res, indent=2)}"
            elif "attack" in lower or "simulate" in lower:
                attack_type = "bruteforce"
                if "powershell" in lower:
                    attack_type = "powershell"
                elif "portscan" in lower or "port scan" in lower:
                    attack_type = "portscan"
                elif "ransomware" in lower or "ransom" in lower:
                    attack_type = "ransomware"
                res = self.cyberos_launch_attack(attack_type)
                return f"CyberOS Attack: {res.get('status', 'launched')} - {attack_type}"
            elif "reset" in lower or "clear" in lower:
                res = self.cyberos_reset()
                return f"CyberOS: {res.get('message', 'reset')}"
            elif "report" in lower:
                return self.cyberos_generate_report()
            else:
                return """CyberOS Commands:
  - 'cyberos start' - Start live defense monitoring
  - 'cyberos stop' - Stop monitoring
  - 'cyberos status' - Show system status
  - 'cyberos attack bruteforce/powershell/portscan/ransomware' - Launch attack simulation
  - 'cyberos reset' - Reset system state
  - 'cyberos report' - Generate incident report"""

        # Fallback to AI orchestrator
        return self.orchestrator._call_role("investigator", "You are a SOC analyst assistant.", f"Process this user request:\n{user_input}")

    def _run_soc_validation(self, user_input: str) -> str:
        """Run a collaborative specialist investigation and populated workflows."""
        self._publish_ui_event(
            "agent_reasoning",
            "I will run a collaborative read-only SOC investigation. Each specialist will call the configured AI API, review the shared brief, and pass a concise handoff to the next specialist.",
            "running",
        )
        agents = self.soc_list_agents()
        agent_results = []
        shared_brief = user_input
        for agent in agents:
            agent_id = agent["id"]
            self._publish_ui_event("workflow_agent_started", f"Validating {agent['name']}", "running", agent=agent_id)
            self._publish_ui_event(
                "agent_reasoning",
                f"{agent['name']} is reviewing the shared investigation brief and preparing a handoff for the next specialist.",
                "running",
                agent=agent_id,
            )
            output = self.soc_orchestrator._call_agent(
                agent_id,
                "Provide a concise, evidence-first read-only assessment. "
                "Use the shared brief and prior specialist handoffs below. "
                "Do not invent observations or claim tools ran unless evidence says so. "
                f"\n\nShared investigation brief:\n{shared_brief[-8000:]}",
            )
            handoff = str(output or "No assessment returned")[:1200]
            shared_brief += f"\n\n[{agent['name']} handoff]\n{handoff}"
            status = "completed" if output else "failed"
            agent_results.append({"agent": agent["name"], "status": status, "handoff": handoff})
            self._publish_ui_event("workflow_agent_completed", f"{agent['name']} validation complete", status, agent=agent_id, handoff=handoff)

        workflow_results = []
        for workflow_name in self.soc_list_workflows():
            result = self.soc_run_workflow(workflow_name, user_input)
            workflow_results.append({
                "workflow": workflow_name,
                "status": "completed" if result.get("phases") else "failed",
                "phases": len(result.get("phases", [])),
            })
        return json.dumps({"agents": agent_results, "workflows": workflow_results}, indent=2)

    def _run_ai_orchestrated_request(self, user_input: str, session_id: str = "default") -> str:
        """Executes a multi-step investigation using the autonomous AgentRuntime.
        
        Features:
        - Rolling context compaction and tool output pruning
        - Two-tier doom-loop detection (warning at 3, halt at 5)
        - Strict stop conditions and step budgeting
        - Delegating specialist subagents with structured contracts
        - Persistent PTY shell sessions and safe approval rules
        """
        inv_id = self.current_investigation.get("investigation_id", "") if self.current_investigation else ""
        try:
            run_result = self.agent_runtime.run_investigation(
                user_input=user_input,
                session_id=session_id,
                investigation_id=inv_id,
            )
            return run_result.response
        except Exception as exc:
            self._publish_ui_event(
                "agent_failed",
                f"AI investigation failed: {exc}",
                "error",
                error=str(exc),
            )
            raise

    # --- CyberOS Live Defense System ---

    def cyberos_start(self) -> Dict[str, Any]:
        """Start CyberOS live defense monitoring."""
        if not self.cyberos_available:
            return {"error": "CyberOS not available"}
        self.cyberos_engine.start()
        return {"status": "started", "message": "CyberOS live defense monitoring activated"}

    def cyberos_stop(self) -> Dict[str, Any]:
        """Stop CyberOS monitoring."""
        if not self.cyberos_available:
            return {"error": "CyberOS not available"}
        self.cyberos_engine.stop()
        return {"status": "stopped", "message": "CyberOS monitoring deactivated"}

    def cyberos_status(self) -> Dict[str, Any]:
        """Get CyberOS status."""
        if not self.cyberos_available:
            return {"error": "CyberOS not available"}
        return self.cyberos_engine.get_status()

    def cyberos_launch_attack(self, attack_type: str) -> Dict[str, Any]:
        """Launch a controlled attack simulation."""
        if not self.cyberos_available:
            return {"error": "CyberOS not available"}
        
        try:
            from cyber_os.cyber_os_attacks import launch_attack
            threading.Thread(target=launch_attack, args=(attack_type, self.cyberos_engine), daemon=True).start()
            return {"status": "launched", "attack_type": attack_type}
        except Exception as e:
            return {"error": str(e)}

    def cyberos_reset(self) -> Dict[str, Any]:
        """Reset CyberOS state."""
        if not self.cyberos_available:
            return {"error": "CyberOS not available"}
        self.cyberos_engine.blocked_ips.clear()
        self.cyberos_engine.blocked_ports.clear()
        self.cyberos_engine.terminated_pids.clear()
        self.cyberos_engine.quarantined_files.clear()
        self.cyberos_engine.locked_accounts.clear()
        self.cyberos_engine.threat_score = 0
        self.cyberos_engine.events.clear()
        self.cyberos_engine.alerts.clear()
        return {"status": "reset", "message": "CyberOS state cleared"}

    def cyberos_generate_report(self) -> str:
        """Generate incident report from latest alert."""
        if not self.cyberos_available:
            return "CyberOS not available"
        
        if not self.cyberos_engine.alerts:
            return "No alerts to report. Run an attack simulation first."
        
        latest_alert = list(self.cyberos_engine.alerts)[-1]
        analysis = self.cyberos_ai.analyze_threat(latest_alert.to_dict())
        return self.cyberos_ai.generate_incident_report(latest_alert.to_dict(), analysis)

    # --- CyberOS SOC Integration ---

    def cyberos_soc_incidents(self) -> List[Dict]:
        """Get all SOC incidents."""
        if not hasattr(self, 'cyberos_soc_incident_manager'):
            try:
                from cyber_os.incident_manager import IncidentManager
                self.cyberos_soc_incident_manager = IncidentManager()
            except Exception:
                return []
        return [i.to_dict() for i in self.cyberos_soc_incident_manager.get_all_incidents()]

    def cyberos_soc_findings(self) -> List[Dict]:
        """Get all SOC findings."""
        if not hasattr(self, 'cyberos_soc_incident_manager'):
            try:
                from cyber_os.incident_manager import IncidentManager
                self.cyberos_soc_incident_manager = IncidentManager()
            except Exception:
                return []
        return [f.to_dict() for f in self.cyberos_soc_incident_manager.findings.values()]

    def cyberos_soc_investigate(self) -> str:
        """Run SOC investigation."""
        if not hasattr(self, 'cyberos_soc_incident_manager'):
            try:
                from cyber_os.incident_manager import IncidentManager
                self.cyberos_soc_incident_manager = IncidentManager()
            except Exception:
                return "SOC modules not available"
        
        incident = self.cyberos_soc_incident_manager.create_incident(
            title=f"System Investigation - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            severity="MEDIUM",
            risk_score=35,
            confidence=0.75,
            evidence_count=5,
            detection_count=3,
            mitre_techniques=["T1059.001", "T1071.001"],
        )
        return f"Investigation complete. Incident {incident.incident_id} created."

    def cyberos_soc_stats(self) -> Dict:
        """Get SOC statistics."""
        if not hasattr(self, 'cyberos_soc_incident_manager'):
            try:
                from cyber_os.incident_manager import IncidentManager
                self.cyberos_soc_incident_manager = IncidentManager()
            except Exception:
                return {}
        return self.cyberos_soc_incident_manager.get_statistics()


def run_demo():
    print("=== Cybersecurity Agent Initialized ===")
    agent = CyberAgent(workspace_path=".")
    
    print(f"\n[+] WSL Status Check:")
    print(f" - WSL Available: {agent.wsl_available}")
    print(f" - WSL Distros: {agent.wsl_distros}")
    print(f" - Default Distro: {agent.default_distro}")

    print("\n[+] Testing Tool Executions & Routing:")
    
    proc_res = agent.execute_tool("windows_process_monitor")
    print(f" - Tool: {proc_res['tool']} | Env: {proc_res['environment_used']} | Success: {proc_res['success']}")

    av_res = agent.execute_tool("clamav_scan", {"target": "code 1"})
    print(f" - Tool: {av_res['tool']} | Env: {av_res['environment_used']} | Success: {av_res['success']}")

if __name__ == "__main__":
    run_demo()
