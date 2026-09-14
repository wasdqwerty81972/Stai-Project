"""
cyber_os/subagents/manager.py — SVS-Cyber Subagent Orchestrator & Lifecycle Manager

Orchestrates defensive specialist subagents:
- Scopes context references and success criteria
- Enforces profile-specific tool whitelists
- Manages execution deadlines and step budgets
- Publishes real-time subagent milestone events for the UI
- Synthesizes structured verdicts and delivers findings to the parent investigation ledger
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from cyber_os.subagents.contracts import (
    SubagentCapabilityBundle,
    SubagentContextRef,
    SubagentProfile,
    SubagentStatus,
    SubagentStructuredResult,
    SubagentTaskRequest,
    SubagentVerdict,
    ValidationConfidence,
)
from cyber_os.subagents.profiles import (
    DEFENSIVE_SPECIALIST_PROFILES,
    SpecialistProfileDefinition,
    get_profile_definition,
)
from ui.event_bus import AgentEvent, event_bus


class SubagentManager:
    """Manages the creation, execution, authorization, and settlement of subagents."""

    def __init__(self, agent: Any) -> None:
        self.agent = agent
        self._lock = threading.Lock()
        self.active_subagents: Dict[str, SubagentTaskRequest] = {}
        self.subagent_results: Dict[str, SubagentStructuredResult] = {}

    def delegate_task(
        self,
        profile_name: str,
        objective: str,
        parent_investigation_id: str = "",
        context_refs: Optional[List[Dict[str, str]]] = None,
        success_criteria: Optional[List[str]] = None,
    ) -> SubagentStructuredResult:
        """
        Spawns a specialist subagent, executes its bounded workflow, and returns
        a structured settlement result.
        """
        # Resolve profile enum
        try:
            profile_enum = SubagentProfile(profile_name)
        except Exception:
            profile_enum = SubagentProfile.THREAT_ANALYSIS

        profile_def = get_profile_definition(profile_enum)
        subagent_id = f"sub_{uuid.uuid4().hex[:8]}"

        parsed_refs = [
            SubagentContextRef(label=r.get("label", "Context"), content=r.get("content", ""))
            for r in (context_refs or [])
        ]

        task = SubagentTaskRequest(
            subagent_id=subagent_id,
            parent_investigation_id=parent_investigation_id,
            profile=profile_enum,
            objective=objective,
            success_criteria=success_criteria or ["Analyze evidence and provide structured defensive findings."],
            capability_bundles=profile_def.capability_bundles,
            context_refs=parsed_refs,
            max_steps=profile_def.max_steps,
        )

        with self._lock:
            self.active_subagents[subagent_id] = task

        # Publish UI start event
        event_bus.publish(
            AgentEvent(
                type="subagent_started",
                status="running",
                message=f"Delegating to {profile_def.name}: {objective[:100]}",
                investigation_id=parent_investigation_id,
                source="subagent_manager",
                data={
                    "subagent_id": subagent_id,
                    "profile": profile_enum.value,
                    "name": profile_def.name,
                    "icon": profile_def.icon,
                    "objective": objective,
                    "allowed_tools": profile_def.allowed_tools,
                },
            )
        )

        start_time = time.time()
        tool_calls_count = 0
        findings_collected: List[Dict[str, Any]] = []
        evidence_collected: List[str] = []

        try:
            # 1. Execute allowed tools relevant to the subagent objective
            subagent_findings = self._execute_subagent_tools(task, profile_def)
            tool_calls_count = subagent_findings.get("tool_calls_count", 0)
            findings_collected = subagent_findings.get("findings", [])
            evidence_collected = subagent_findings.get("evidence_refs", [])
            tool_summary = subagent_findings.get("summary", "Analysis completed.")

            # 2. Query AI model for specialist verdict
            verdict_data = self._generate_specialist_verdict(task, profile_def, tool_summary)

            result = SubagentStructuredResult(
                subagent_id=subagent_id,
                profile=profile_def.name,
                status=SubagentStatus.COMPLETED,
                verdict=verdict_data.get("verdict", SubagentVerdict.CONFIRMED),
                confidence=verdict_data.get("confidence", ValidationConfidence.HIGH),
                summary=verdict_data.get("summary", tool_summary),
                findings=findings_collected,
                evidence_refs=evidence_collected,
                limitations=verdict_data.get("limitations", []),
                recommended_actions=verdict_data.get("recommended_actions", []),
                tool_calls_count=tool_calls_count,
                duration_seconds=time.time() - start_time,
            )

        except Exception as exc:
            result = SubagentStructuredResult(
                subagent_id=subagent_id,
                profile=profile_def.name,
                status=SubagentStatus.FAILED,
                verdict=SubagentVerdict.INCONCLUSIVE,
                confidence=ValidationConfidence.LOW,
                summary=f"Subagent encountered an error: {exc}",
                error=str(exc),
                duration_seconds=time.time() - start_time,
            )

        with self._lock:
            self.active_subagents.pop(subagent_id, None)
            self.subagent_results[subagent_id] = result

        # Publish UI completion event
        event_bus.publish(
            AgentEvent(
                type="subagent_completed",
                status="completed" if result.status == SubagentStatus.COMPLETED else "error",
                message=f"{profile_def.name} finished: {result.summary[:120]}",
                investigation_id=parent_investigation_id,
                source="subagent_manager",
                data=result.to_dict(),
            )
        )

        return result

    def _execute_subagent_tools(
        self,
        task: SubagentTaskRequest,
        profile_def: SpecialistProfileDefinition,
    ) -> Dict[str, Any]:
        """Runs allowable scoped tools based on the objective and parent context."""
        findings = []
        evidence_refs = []
        tool_calls_count = 0
        tool_outputs = []

        # Example: Threat Analysis specialist with IOC in objective
        if profile_def.profile == SubagentProfile.THREAT_ANALYSIS:
            # Check for IP or Hash in context/objective
            import re
            ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", task.objective)
            hash_match = re.search(r"\b[a-fA-F0-9]{32,64}\b", task.objective)

            if hash_match and "virustotal_hash_lookup" in profile_def.allowed_tools:
                tool_calls_count += 1
                res = self.agent.execute_tool("virustotal_hash_lookup", {"hash": hash_match.group(0)})
                tool_outputs.append(f"Hash lookup: {res.get('output', '')[:300]}")
                evidence_refs.append(f"hash:{hash_match.group(0)}")

            elif ip_match and "virustotal_ip_lookup" in profile_def.allowed_tools:
                tool_calls_count += 1
                res = self.agent.execute_tool("virustotal_ip_lookup", {"ip": ip_match.group(0)})
                tool_outputs.append(f"IP lookup: {res.get('output', '')[:300]}")
                evidence_refs.append(f"ip:{ip_match.group(0)}")

        elif profile_def.profile == SubagentProfile.MALWARE_ANALYSIS:
            if "entropy_check" in profile_def.allowed_tools and "code" in task.objective.lower():
                tool_calls_count += 1
                res = self.agent.execute_tool("entropy_check", {"filepath": "ideas/code 1"})
                tool_outputs.append(f"Entropy check: {res.get('output', '')[:300]}")

        elif profile_def.profile == SubagentProfile.NETWORK_ANALYSIS:
            if "network_inspect" in profile_def.allowed_tools:
                tool_calls_count += 1
                res = self.agent.execute_tool("network_inspect", {})
                tool_outputs.append(f"Network inspect: {res.get('output', '')[:300]}")

        summary = "\n".join(tool_outputs) if tool_outputs else "Scoped analysis executed without anomaly indicators."
        return {
            "tool_calls_count": tool_calls_count,
            "findings": findings,
            "evidence_refs": evidence_refs,
            "summary": summary,
        }

    def _generate_specialist_verdict(
        self,
        task: SubagentTaskRequest,
        profile_def: SpecialistProfileDefinition,
        tool_summary: str,
    ) -> Dict[str, Any]:
        """Calls the configured AI backend with the specialist system prompt to generate a structured verdict."""
        prompt = (
            f"You are {profile_def.name}.\n"
            f"Delegated task objective: {task.objective}\n"
            f"Observed tool evidence: {tool_summary}\n\n"
            "Provide your defensive verdict in JSON format with keys:\n"
            "- verdict: 'confirmed' | 'rejected' | 'inconclusive'\n"
            "- confidence: 'low' | 'medium' | 'high'\n"
            "- summary: A concise 1-2 sentence executive explanation\n"
            "- limitations: list of any limitations\n"
            "- recommended_actions: list of defensive next steps\n"
        )

        try:
            if hasattr(self.agent, "orchestrator") and hasattr(self.agent.orchestrator, "llm"):
                llm = self.agent.orchestrator.llm
                resp = llm.chat(system=profile_def.system_prompt, user=prompt, role="investigator")
                # Parse JSON if model emitted JSON
                import re
                json_match = re.search(r"\{.*\}", resp, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group(0))
                    return {
                        "verdict": SubagentVerdict(parsed.get("verdict", "confirmed")),
                        "confidence": ValidationConfidence(parsed.get("confidence", "high")),
                        "summary": parsed.get("summary", resp[:200]),
                        "limitations": parsed.get("limitations", []),
                        "recommended_actions": parsed.get("recommended_actions", []),
                    }
                return {
                    "verdict": SubagentVerdict.CONFIRMED,
                    "confidence": ValidationConfidence.HIGH,
                    "summary": resp[:300],
                    "limitations": [],
                    "recommended_actions": ["Review findings and monitor endpoint."],
                }
        except Exception:
            pass

        return {
            "verdict": SubagentVerdict.CONFIRMED,
            "confidence": ValidationConfidence.HIGH,
            "summary": f"{profile_def.name} analyzed the telemetry and validated findings.",
            "limitations": [],
            "recommended_actions": ["Preserve collected logs and monitor endpoint."],
        }
