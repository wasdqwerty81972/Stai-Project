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
import re
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
    resolve_profile_definition,
)
from ui.event_bus import AgentEvent, event_bus


# Split by kind because the two consumers want different things: reading a
# .exe as text yields garbage, and running an entropy check on a .md is noise.
# The optional single-letter drive prefix keeps Windows paths whole. Allowing
# ":" inside the body instead would swallow "https://host/payload.py" — a URL
# is not a local file, and handing one to a file tool just fails.
_DRIVE_PREFIX = r"(?:[A-Za-z]:[\\/])?"
_SOURCE_FILE_PATTERN = re.compile(
    _DRIVE_PREFIX
    + r"[\w./\\-]+\.(?:py|js|ts|tsx|jsx|go|rs|java|rb|php|cs|cpp|c|md|json|ya?ml|txt|log|ini|cfg)\b",
    re.I,
)
_BINARY_FILE_PATTERN = re.compile(
    _DRIVE_PREFIX
    + r"[\w./\\-]+\.(?:exe|dll|sys|bin|scr|com|msi|ps1|bat|cmd|vbs|jar|zip|7z|rar|docx?|xlsx?|pdf|dat)\b",
    re.I,
)


def _first_path(task: SubagentTaskRequest, *patterns: re.Pattern) -> str:
    """Return the first file the task actually names, or "" if it names none.

    The objective is searched before the parent context so an explicit
    instruction wins over an incidental filename quoted in the transcript.
    Returning "" is the point: substituting a fixed sample path makes the
    specialist analyse a file the investigation never mentioned and then
    report that result as evidence.
    """
    haystacks = [task.objective or ""]
    haystacks.extend((ref.content or "") for ref in (task.context_refs or []))
    for text in haystacks:
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                return match.group(0)
    return ""


def _coerce_verdict(value: Any) -> SubagentVerdict:
    """Map a model-supplied verdict string onto the enum without raising."""
    try:
        return SubagentVerdict(str(value).strip().lower())
    except (ValueError, TypeError):
        return SubagentVerdict.INCONCLUSIVE


def _coerce_confidence(value: Any) -> ValidationConfidence:
    """Map a model-supplied confidence string onto the enum without raising."""
    try:
        return ValidationConfidence(str(value).strip().lower())
    except (ValueError, TypeError):
        return ValidationConfidence.LOW


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
        # Resolve the delegation target. Covers the ten hand-written defensive
        # Resolve the delegation target. Covers the ten hand-written defensive
        # specialists and the markdown definitions in subagents/definitions/.
        # An unknown name is rejected outright: previously it ran Threat
        # Analysis instead, so a typo appeared to work while running a
        # different specialist than the caller asked for.
        profile_enum, profile_def, profile_origin = resolve_profile_definition(profile_name)
        subagent_id = f"sub_{uuid.uuid4().hex[:8]}"

        if profile_origin == "fallback":
            error = (
                f"Unknown specialist {profile_name!r}. It is neither a built-in "
                "defensive profile nor a definition in subagents/definitions/. "
                "No subagent was run."
            )
            result = SubagentStructuredResult(
                subagent_id=subagent_id,
                profile=(profile_name or "").strip() or "<empty>",
                status=SubagentStatus.FAILED,
                verdict=SubagentVerdict.INCONCLUSIVE,
                confidence=ValidationConfidence.LOW,
                summary=error,
                limitations=[error],
                error=error,
            )
            with self._lock:
                self.subagent_results[subagent_id] = result
            event_bus.publish(
                AgentEvent(
                    type="subagent_failed",
                    status="error",
                    message=error,
                    investigation_id=parent_investigation_id,
                    source="subagent_manager",
                    data={
                        **result.to_dict(),
                        "requested_profile": profile_name,
                        "profile_origin": profile_origin,
                    },
                )
            )
            return result

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
                    "requested_profile": profile_name,
                    "profile_origin": profile_origin,
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
            candidate = _first_path(task, _BINARY_FILE_PATTERN, _SOURCE_FILE_PATTERN)
            if candidate and "entropy_check" in profile_def.allowed_tools:
                tool_calls_count += 1
                res = self.agent.execute_tool("entropy_check", {"filepath": candidate})
                tool_outputs.append(f"Entropy check on '{candidate}': {res.get('output', '')[:300]}")
                evidence_refs.append(f"file:{candidate}")

        elif profile_def.profile == SubagentProfile.NETWORK_ANALYSIS:
            if "network_inspect" in profile_def.allowed_tools:
                tool_calls_count += 1
                res = self.agent.execute_tool("network_inspect", {})
                tool_outputs.append(f"Network inspect: {res.get('output', '')[:300]}")

        else:
            # Markdown-defined specialists carry SubagentProfile.GENERAL. Without
            # this branch their declared allowed_tools were never exercised, so
            # a definition could list a tool and still never call it. Every call
            # below is gated on the profile's own allowlist and stays read-only.
            tool_outputs, evidence_refs, tool_calls_count = self._run_markdown_tools(
                task, profile_def, tool_outputs, evidence_refs, tool_calls_count
            )

        summary = "\n".join(tool_outputs) if tool_outputs else "Scoped analysis executed without anomaly indicators."
        return {
            "tool_calls_count": tool_calls_count,
            "findings": findings,
            "evidence_refs": evidence_refs,
            "summary": summary,
        }

    def _run_markdown_tools(
        self,
        task: SubagentTaskRequest,
        profile_def: SpecialistProfileDefinition,
        tool_outputs: List[str],
        evidence_refs: List[str],
        tool_calls_count: int,
    ) -> tuple:
        """Bounded read-only tool use for a markdown-defined specialist.

        Only tools the definition itself declared are invoked, and only
        workspace-confined read-only ones. Returns the updated accumulators.
        """
        allowed = set(profile_def.allowed_tools)
        objective = task.objective or ""

        candidate = _first_path(task, _SOURCE_FILE_PATTERN)
        if candidate and "workspace_read_file" in allowed:
            res = self.agent.execute_tool("workspace_read_file", {"filepath": candidate})
            tool_calls_count += 1
            tool_outputs.append(
                f"Read '{candidate}': {str(res.get('output') or res.get('error', ''))[:300]}"
            )
            evidence_refs.append(f"file:{candidate}")
            return tool_outputs, evidence_refs, tool_calls_count

        if "workspace_list_files" in allowed and any(
            word in objective.lower()
            for word in ("list", "files", "directory", "folder", "repo", "tree")
        ):
            res = self.agent.execute_tool("workspace_list_files", {"root": "."})
            tool_calls_count += 1
            tool_outputs.append(f"Listed workspace: {str(res.get('output') or res.get('error', ''))[:300]}")
            evidence_refs.append("workspace:.")

        return tool_outputs, evidence_refs, tool_calls_count

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
            resp = self._call_specialist_llm(profile_def.system_prompt, prompt)
            if resp:
                json_match = re.search(r"\{.*\}", resp, re.DOTALL)
                if json_match:
                    try:
                        parsed = json.loads(json_match.group(0))
                    except (json.JSONDecodeError, ValueError):
                        parsed = {}
                    if parsed:
                        return {
                            "verdict": _coerce_verdict(parsed.get("verdict")),
                            "confidence": _coerce_confidence(parsed.get("confidence")),
                            "summary": parsed.get("summary", resp[:200]),
                            "limitations": parsed.get("limitations", []),
                            "recommended_actions": parsed.get("recommended_actions", []),
                        }
                return {
                    "verdict": SubagentVerdict.INCONCLUSIVE,
                    "confidence": ValidationConfidence.MEDIUM,
                    "summary": resp[:300],
                    "limitations": ["The specialist returned prose rather than a structured JSON verdict."],
                    "recommended_actions": ["Review findings and monitor endpoint."],
                }
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        else:
            last_error = "no AI backend is configured for specialist verdicts"

        # No usable verdict. Report inconclusive rather than a fabricated
        # confirmation: a specialist that did not actually reason must not look
        # like one that validated the telemetry.
        return {
            "verdict": SubagentVerdict.INCONCLUSIVE,
            "confidence": ValidationConfidence.LOW,
            "summary": f"{profile_def.name} could not produce a model verdict: {last_error}.",
            "limitations": [last_error],
            "recommended_actions": ["Preserve collected logs and monitor endpoint."],
        }

    def _call_specialist_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Invoke whatever AI backend the owning agent exposes.

        CyberAgent carries a ``CyberSecurityOrchestrator`` (``_call_role``), not
        a ``ToolOrchestrator`` (``.llm``). Testing only for ``.llm`` meant this
        path never ran and every verdict silently fell through to the canned
        stub. Both shapes are supported here so the specialist actually reasons.
        """
        orchestrator = getattr(self.agent, "orchestrator", None)
        if orchestrator is None:
            return ""

        if hasattr(orchestrator, "_call_role"):
            response = orchestrator._call_role("investigator", system_prompt, user_prompt)
        elif hasattr(orchestrator, "llm"):
            response = orchestrator.llm.chat(system=system_prompt, user=user_prompt, role="investigator")
        else:
            return ""

        response = (response or "").strip()
        if not response or response.startswith("[AI ERROR]"):
            return ""
        if "provider unavailable" in response.lower():
            return ""
        return response
