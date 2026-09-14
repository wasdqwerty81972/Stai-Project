"""
cyber_os/agent_runtime.py — SVS-Cyber Resilient Multi-Step Agent Runtime

Implements the multi-step investigation loop adapting the best architectural patterns
from mature agent platform engines into SVS-Cyber.

Features:
- Multi-step iterative reasoning & tool loop
- PrepareStep: rolling context compaction & older tool output pruning
- DoomLoopDetector: 2-tier warning nudge and halt threshold
- StopConditions: explicit finish reasons (step limit, timeout, tokens, cancellation)
- ApprovalEngine integration: session prefix rules, shell injection protection
- SubagentManager integration: bounded specialist delegation
- Real-time event streaming over the UI event bus
- Structured investigation persistence
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from cyber_os.approval_engine import ApprovalEngine
from cyber_os.compaction import ContextCompactor, estimate_tokens
from cyber_os.doom_loop_detector import DoomLoopDetector, DoomLoopSeverity
from cyber_os.pty_session_manager import PtySessionManager
from cyber_os.stop_conditions import FinishReason, StopConditions
from cyber_os.subagents.manager import SubagentManager
from cyber_os.system_prompt import SystemPromptComposer
from ui.event_bus import AgentEvent, event_bus


@dataclass
class AgentRunResult:
    success: bool
    response: str
    investigation_id: str
    session_id: str
    steps_executed: int
    findings: List[Dict[str, Any]] = field(default_factory=list)
    finish_reason: str = "complete"
    finish_message: str = ""
    duration_seconds: float = 0.0


class AgentRuntime:
    """The central SVS-Cyber agent runtime engine."""

    def __init__(self, agent: Any) -> None:
        self.agent = agent
        self.compactor = ContextCompactor()
        self.doom_loop_detector = DoomLoopDetector()
        self.stop_conditions = StopConditions(max_steps=15, max_elapsed_seconds=300.0)
        self.pty_manager = PtySessionManager.get_instance()
        self.approval_engine = ApprovalEngine()
        self.subagent_manager = SubagentManager(agent)
        self._active_runs: Dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def run_investigation(
        self,
        user_input: str,
        session_id: str = "default",
        investigation_id: Optional[str] = None,
        custom_instructions: str = "",
    ) -> AgentRunResult:
        """
        Executes a complete, resilient multi-step defensive investigation.
        """
        inv_id = investigation_id or f"inv_{uuid.uuid4().hex[:10]}"
        start_time = time.time()
        cancel_event = getattr(self.agent, "cancel_event", threading.Event())
        cancel_event.clear()

        with self._lock:
            self._active_runs[inv_id] = cancel_event

        self.doom_loop_detector.reset()
        self.stop_conditions.reset()

        # 1. Compose modular system prompt
        tasks = self.agent.task_manager.get_tasks() if hasattr(self.agent, "task_manager") else []
        notes = self.agent.notes_manager.list_notes() if hasattr(self.agent, "notes_manager") else []
        system_prompt = SystemPromptComposer.build_system_prompt(
            custom_instructions=custom_instructions,
            workspace_path=getattr(self.agent, "workspace_path", "."),
            active_tasks=tasks,
            active_notes=notes,
            available_tools=[
                tool.to_manifest()
                for tool in getattr(self.agent.registry, "tools", {}).values()
            ],
        )

        # 2. Publish lifecycle events
        event_bus.publish(
            AgentEvent(
                type="investigation_started",
                status="running",
                message=f"Investigation started: {user_input[:80]}",
                session_id=session_id,
                investigation_id=inv_id,
                source="agent_runtime",
                data={"objective": user_input, "investigation_id": inv_id},
            )
        )

        event_bus.publish(
            AgentEvent(
                type="agent_started",
                status="running",
                message="Agent is analyzing the request",
                session_id=session_id,
                investigation_id=inv_id,
                source="agent_runtime",
            )
        )

        steps_record: List[Dict[str, Any]] = []
        findings_collected: List[Dict[str, Any]] = []
        conversation_context = f"User Request: {user_input}\n"
        final_response = ""
        response_published = False

        try:
            while not self.stop_conditions.should_stop(is_cancelled=cancel_event.is_set()):
                step_idx = self.stop_conditions.steps_executed + 1

                # Check for cancellation at each step
                if cancel_event.is_set():
                    finish_reason = "cancelled"
                    final_response = "Investigation was cancelled by user."
                    self.stop_conditions.finish_reason = FinishReason.CANCELLED
                    self.stop_conditions.finish_message = "Cancelled by user"
                    event_bus.publish(
                        AgentEvent(
                            type="agent_cancelled",
                            status="cancelled",
                            message="Investigation was cancelled by user",
                            session_id=session_id,
                            investigation_id=inv_id,
                            source="agent_runtime",
                        )
                    )
                    break

                # A. Prepare Step: Prune older tool outputs if tokens grow large
                prune_result = self.compactor.prune_tool_steps(steps_record)
                if prune_result.pruned_count > 0:
                    steps_record = prune_result.steps

                # B. Determine Next Action using Live Model or Specialist Heuristics
                step_decision = self._decide_next_step(
                    user_input=user_input,
                    system_prompt=system_prompt,
                    conversation_context=conversation_context,
                    steps_record=steps_record,
                    findings=findings_collected,
                    step_index=step_idx,
                )

                action_type = step_decision.get("action_type")  # 'tool', 'subagent', 'final_answer'

                # --- Path 1: Final Answer ---
                if action_type == "final_answer":
                    final_response = step_decision.get("response", "Investigation concluded.")
                    self.publish_activity(session_id, inv_id, "Synthesizing final answer...", "running")
                    self.stop_conditions.record_step(tokens_used=estimate_tokens(final_response))
                    
                    # Publish agent_completed event before breaking
                    event_bus.publish(
                        AgentEvent(
                            type="agent_completed",
                            status="completed",
                            message="Investigation complete",
                            session_id=session_id,
                            investigation_id=inv_id,
                            source="agent_runtime",
                            data={"response": final_response[:500]},
                        )
                    )
                    # Publish response event with the final answer (frontend renders this as assistant text)
                    event_bus.publish(
                        AgentEvent(
                            type="response",
                            status="completed",
                            message=final_response,
                            session_id=session_id,
                            investigation_id=inv_id,
                            source="agent_runtime",
                            data={"finish_reason": "complete"},
                        )
                    )
                    response_published = True
                    self.publish_activity(session_id, inv_id, final_response[:300], "completed")
                    break

                # --- Path 2: Subagent Delegation ---
                elif action_type == "subagent":
                    subagent_profile = step_decision.get("profile", "threat_analysis")
                    subagent_objective = step_decision.get("objective", user_input)
                    event_bus.publish(
                        AgentEvent(
                            type="agent_reasoning",
                            status="running",
                            message=f"Delegating scoped task to {subagent_profile}: {subagent_objective[:80]}",
                            session_id=session_id,
                            investigation_id=inv_id,
                            source="agent_runtime",
                        )
                    )
                    subagent_result = self.subagent_manager.delegate_task(
                        profile_name=subagent_profile,
                        objective=subagent_objective,
                        parent_investigation_id=inv_id,
                    )
                    self.stop_conditions.record_step(tokens_used=500)

                    steps_record.append({
                        "step": step_idx,
                        "type": "subagent",
                        "profile": subagent_profile,
                        "objective": subagent_objective,
                        "verdict": subagent_result.verdict.value,
                        "output": subagent_result.summary,
                    })

                    conversation_context += (
                        f"\n[Subagent '{subagent_result.profile}' Result]: "
                        f"Verdict: {subagent_result.verdict.value} (Confidence: {subagent_result.confidence.value})\n"
                        f"{subagent_result.summary}\n"
                    )

                    if subagent_result.findings:
                        findings_collected.extend(subagent_result.findings)

                # --- Path 3: Tool Execution ---
                elif action_type == "tool":
                    tool_name = step_decision.get("tool_name", "")
                    tool_args = step_decision.get("arguments", {})
                    brief = step_decision.get("brief", f"Executing {tool_name}")

                    # Check for cancellation before executing
                    if cancel_event.is_set():
                        finish_reason = "cancelled"
                        final_response = "Investigation was cancelled by user."
                        self.stop_conditions.finish_reason = FinishReason.CANCELLED
                        self.stop_conditions.finish_message = "Cancelled by user"
                        event_bus.publish(
                            AgentEvent(
                                type="agent_cancelled",
                                status="cancelled",
                                message="Investigation was cancelled by user",
                                session_id=session_id,
                                investigation_id=inv_id,
                                source="agent_runtime",
                            )
                        )
                        break

                    # Doom loop detection check
                    loop_eval = self.doom_loop_detector.record_step(tool_name, tool_args)
                    if loop_eval.severity == DoomLoopSeverity.HALT:
                        self.stop_conditions.should_stop(doom_loop_halt=True)
                        final_response = loop_eval.nudge_message or "Investigation halted due to repetitive loop."
                        self.publish_activity(session_id, inv_id, "Investigation halted: doom loop detected", "error")
                        event_bus.publish(
                            AgentEvent(
                                type="agent_error",
                                status="error",
                                message=final_response,
                                session_id=session_id,
                                investigation_id=inv_id,
                                source="agent_runtime",
                                data={"reason": "doom_loop_detected"},
                            )
                        )
                        break
                    elif loop_eval.severity == DoomLoopSeverity.WARNING:
                        safety_msg = loop_eval.nudge_message
                        conversation_context += f"\n[System Safety Nudge]: {safety_msg}\n"
                        self.publish_activity(session_id, inv_id, safety_msg, "running")

                    # Publish agent_reasoning for the decision (execute_tool will publish tool_started/completed)
                    self.publish_activity(session_id, inv_id, brief or f"Decided to use {tool_name}", "running")

                    # Execute tool via CyberAgent (which publishes tool_started/completed/failed/cancelled events)
                    exec_result = self.agent.execute_tool(tool_name, tool_args)
                    tool_success = exec_result.get("success", False)
                    error = exec_result.get("error")
                    raw_out = str(exec_result.get("output") or error or "")

                    # Automatic screenshot capture for browser tools
                    screenshot_path = None
                    if tool_success and tool_name in ("web_search", "open_url"):
                        try:
                            from Tools_cyber.browser_manager import BrowserManager
                            bm = BrowserManager.get_instance()
                            screenshot_name = f"agent_{tool_name}_{step_idx}_{int(time.time())}.png"
                            screenshot_path = f"D:/STAI 2/.stai/{screenshot_name}"
                            bm.page.screenshot(path=screenshot_path)
                            print(f"[AgentRuntime] Screenshot saved: {screenshot_path}")
                        except Exception as se:
                            print(f"[AgentRuntime] Screenshot capture failed: {se}")

                    # Bounded output truncation for context safety
                    trimmed_out = raw_out[:8000] if len(raw_out) > 8000 else raw_out
                    tokens_used = estimate_tokens(trimmed_out)
                    self.stop_conditions.record_step(tokens_used=tokens_used)

                    steps_record.append({
                        "step": step_idx,
                        "tool": tool_name,
                        "arguments": tool_args,
                        "success": tool_success,
                        "output": trimmed_out,
                    })

                    conversation_context += f"\n[Tool '{tool_name}' Result (Success={tool_success})]:\n{trimmed_out[:1500]}\n"

                    # Publish agent_reasoning for analyzing results
                    if tool_success:
                        self.publish_activity(session_id, inv_id, f"Analyzing {tool_name} results...", "running")
                    elif error:
                        self.publish_activity(session_id, inv_id, f"{tool_name} failed: {error[:200]}", "error")

                    # Check if tool result is sufficient, trigger recovery if not
                    if tool_success and not self._is_result_sufficient(tool_name, trimmed_out, step_idx):
                        recovery_decision = self._llm_recovery_decision(
                            user_input=user_input,
                            system_prompt=system_prompt,
                            conversation_context=conversation_context,
                            failed_tool=tool_name,
                            failed_args=tool_args,
                            failed_output=f"Result may be insufficient: {trimmed_out[:300]}",
                        )
                        if recovery_decision:
                            conversation_context += f"\n[Recovery] Insufficient result from {tool_name}, planning alternative approach\n"
                            self.publish_activity(session_id, inv_id, f"Recovery: trying alternative approach for {tool_name}", "running")
                            recovery_decision["_deferred_recovery"] = True
                            if not hasattr(self, '_deferred_recovery'):
                                self._deferred_recovery = []
                            self._deferred_recovery.append(recovery_decision)
                    if "finding" in exec_result or "threat" in raw_out.lower():
                        new_finding = {
                            "id": f"find_{uuid.uuid4().hex[:6]}",
                            "tool": tool_name,
                            "title": f"Finding from {tool_name}",
                            "severity": "medium",
                            "evidence": raw_out[:300],
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                        findings_collected.append(new_finding)
                        event_bus.publish(
                            AgentEvent(
                                type="finding_created",
                                status="created",
                                message=new_finding["title"],
                                session_id=session_id,
                                investigation_id=inv_id,
                                source="agent_runtime",
                                data=new_finding,
                            )
                        )

                else:
                    # Default: complete
                    break

        except Exception as exc:
            final_response = f"Investigation encountered an unexpected error: {exc}"
            self.stop_conditions.finish_reason = FinishReason.ERROR
            self.stop_conditions.finish_message = str(exc)

        # If loop finished without an explicit final response, synthesize one
        if not final_response:
            final_response = self._synthesize_final_report(
                user_input=user_input,
                system_prompt=system_prompt,
                conversation_context=conversation_context,
                findings=findings_collected,
            )

        duration = time.time() - start_time
        finish_reason_val = (
            self.stop_conditions.finish_reason.value
            if self.stop_conditions.finish_reason
            else FinishReason.COMPLETE.value
        )

        event_bus.publish(
            AgentEvent(
                type="investigation_completed",
                status="completed" if finish_reason_val == "complete" else "finished",
                message=f"Investigation completed: {len(findings_collected)} finding(s)",
                session_id=session_id,
                investigation_id=inv_id,
                source="agent_runtime",
                data={
                    "investigation_id": inv_id,
                    "findings_count": len(findings_collected),
                    "finish_reason": finish_reason_val,
                    "duration_seconds": round(duration, 2),
                },
            )
        )

        # If final response was synthesized (not published via the final_answer action path above),
        # publish a response event now so the frontend renders it
        if not response_published and finish_reason_val != "cancelled":
            event_bus.publish(
                AgentEvent(
                    type="response",
                    status="completed" if finish_reason_val == "complete" else "error",
                    message=final_response,
                    session_id=session_id,
                    investigation_id=inv_id,
                    source="agent_runtime",
                    data={"finish_reason": finish_reason_val},
                )
            )

        with self._lock:
            self._active_runs.pop(inv_id, None)

        return AgentRunResult(
            success=finish_reason_val == "complete",
            response=final_response,
            investigation_id=inv_id,
            session_id=session_id,
            steps_executed=self.stop_conditions.steps_executed,
            findings=findings_collected,
            finish_reason=finish_reason_val,
            finish_message=self.stop_conditions.finish_message or "Complete",
            duration_seconds=duration,
        )

    def publish_activity(self, session_id: str, investigation_id: str, message: str, status: str = "running", **extra: Any) -> None:
        """Publish an agent_reasoning event for UI activity display."""
        event_bus.publish(
            AgentEvent(
                type="agent_reasoning",
                status=status,
                message=message,
                session_id=session_id,
                investigation_id=investigation_id,
                source="agent_runtime",
                data=extra,
            )
        )

    def _decide_next_step(
        self,
        user_input: str,
        system_prompt: str,
        conversation_context: str,
        steps_record: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        step_index: int,
    ) -> Dict[str, Any]:
        """Decides the next action (tool, subagent, or final answer) using LLM-based reasoning."""
        # Use LLM to decide next action (works for step 1 and step 2+)
        decision = self._llm_decide_action(
            user_input=user_input,
            system_prompt=system_prompt,
            conversation_context=conversation_context,
            steps_record=steps_record,
            findings=findings,
            step_index=step_index,
        )
        
        # Handle recovery: if last tool failed and we haven't tried recovery yet
        if step_index > 1 and steps_record:
            last_step = steps_record[-1]
            if last_step.get("success") is False and not decision.get("is_recovery"):
                # Try recovery by asking LLM for alternative approach
                recovery_decision = self._llm_recovery_decision(
                    user_input=user_input,
                    system_prompt=system_prompt,
                    conversation_context=conversation_context,
                    failed_tool=last_step.get("tool"),
                    failed_args=last_step.get("arguments"),
                    failed_output=last_step.get("output"),
                )
                if recovery_decision:
                    return recovery_decision
        
        return decision

    def _llm_decide_action(
        self,
        user_input: str,
        system_prompt: str,
        conversation_context: str,
        steps_record: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        step_index: int,
    ) -> Dict[str, Any]:
        """Uses LLM to decide the next action (tool, subagent, or final answer)."""
        
        # Build available tools manifest from agent registry
        available_tools = []
        try:
            for tool in getattr(self.agent.registry, "tools", {}).values():
                name = getattr(tool, 'name', getattr(tool, 'tool_name', str(tool)))
                if name:
                    available_tools.append({"name": name})
        except Exception as e:
            print(f"[AgentRuntime] Failed to build tool manifests: {e}")
        
        # Build context from previous steps
        steps_summary = []
        for s in steps_record:
            if "tool" in s:
                status = "SUCCESS" if s.get("success") else "FAILED"
                steps_summary.append(f"  - {s['tool']}: {status} - {s.get('output', '')[:200]}")
            elif s.get("type") == "subagent":
                steps_summary.append(f"  - Subagent {s.get('profile')}: {s.get('verdict')}")
        
        executed_tools = {s.get("tool") for s in steps_record if "tool" in s}
        
        tool_names = [t.get('name', '') for t in available_tools if isinstance(t, dict)]
        
        prompt = f"""
{conversation_context}

Previous steps:
{chr(10).join(steps_summary) if steps_summary else "  (none)"}

Available tools: {json.dumps(tool_names)}

You are SVS-Cyber, an autonomous cybersecurity investigation agent.
Current step: {step_index}
User objective: {user_input}

Based on the conversation history and available tools, decide the next action.

Consider:
- What tools have already been executed and their results
- Whether the user's objective requires web research (use web_search, open_url)
- Whether it requires local system investigation (network_inspect, windows_defender_scan, etc.)
- Whether findings need to be recorded (notes, todo_write)
- Whether a specialist subagent is needed

Respond with ONLY a JSON object:
{{
  "action_type": "tool" | "subagent" | "final_answer",
  "tool_name": "tool_name_if_tool",
  "arguments": {{}},
  "brief": "one-line description of what this step does",
  "reason": "why this action was chosen",
  "is_recovery": false
}}

If the investigation is complete and you can provide a final answer:
{{
  "action_type": "final_answer",
  "response": "your final answer here",
  "reason": "investigation complete"
}}
"""
        
        try:
            response = self._call_llm(system=system_prompt, user=prompt)
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                decision = json.loads(json_match.group(0))
                
                # Validate decision
                if decision.get("action_type") == "tool":
                    tool_name = decision.get("tool_name")
                    if tool_name and tool_name in getattr(self.agent.registry, "tools", {}):
                        # Build arguments if not provided
                        if not decision.get("arguments"):
                            decision["arguments"] = self._build_tool_args(tool_name, user_input)
                        return decision
                elif decision.get("action_type") == "subagent":
                    return decision
                elif decision.get("action_type") == "final_answer":
                    return decision
        except Exception as e:
            print(f"[AgentRuntime] LLM decision failed: {e}")
        
        # Fallback to heuristic-based decision
        return self._heuristic_decide_action(
            user_input=user_input,
            conversation_context=conversation_context,
            steps_record=steps_record,
            findings=findings,
            step_index=step_index,
        )

    def _heuristic_decide_action(
        self,
        user_input: str,
        conversation_context: str,
        steps_record: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        step_index: int,
    ) -> Dict[str, Any]:
        """Fallback heuristic decision (original keyword-based logic)."""
        lower = user_input.lower()
        executed_tools = {s.get("tool") for s in steps_record if "tool" in s}

        # Web research triggers
        if any(w in lower for w in ("search", "research", "look up", "find", "browse", "web", "documentation", "docs", "latest", "version")):
            if "web_search" not in executed_tools:
                return {
                    "action_type": "tool",
                    "tool_name": "web_search",
                    "arguments": {"query": self._extract_search_query(user_input)},
                    "brief": "Searching the web for relevant information",
                }
            if "open_url" not in executed_tools:
                return {
                    "action_type": "tool",
                    "tool_name": "open_url",
                    "arguments": {"url": self._extract_url_from_context(conversation_context)},
                    "brief": "Opening a relevant URL for detailed information",
                }

        # Network investigation
        if any(w in lower for w in ("network", "port", "connection", "listening")) and "network_inspect" not in executed_tools:
            return {"action_type": "tool", "tool_name": "network_inspect", "arguments": {}, "brief": "Inspecting active network connections and listening sockets"}

        # Malware / File investigation
        if any(w in lower for w in ("malware", "virus", "defender", "download")) and "windows_defender_scan" not in executed_tools:
            scan_target = self.agent._extract_scan_target(user_input) if hasattr(self.agent, "_extract_scan_target") else "."
            return {"action_type": "tool", "tool_name": "windows_defender_scan", "arguments": {"path": scan_target}, "brief": f"Running Windows Defender scan on '{scan_target}'"}

        # Code / SAST analysis
        if any(w in lower for w in ("code", "sast", "source", "script")) and "static_analysis" not in executed_tools:
            return {"action_type": "tool", "tool_name": "static_analysis", "arguments": {"filepath": "ideas/code 1"}, "brief": "Analyzing source code for security vulnerabilities"}

        # Subagent delegation
        executed_subagents = {s.get("profile") for s in steps_record if s.get("type") == "subagent"}
        if ("threat" in lower or "ioc" in lower) and "threat_analysis" not in executed_subagents:
            return {"action_type": "subagent", "profile": "threat_analysis", "objective": f"Analyze threat indicators for: {user_input}"}

        # Note taking
        if any(w in lower for w in ("note", "record", "remember")) and "notes" not in executed_tools:
            return {"action_type": "tool", "tool_name": "notes", "arguments": {"action": "create", "title": "Investigation Note", "content": user_input}, "brief": "Creating investigation note"}

        # Todo tracking
        if any(w in lower for w in ("todo", "task", "plan", "track")) and "todo_write" not in executed_tools:
            return {"action_type": "tool", "tool_name": "todo_write", "arguments": {"todos": [{"id": "1", "text": user_input, "status": "in_progress"}]}, "brief": "Creating investigation task list"}

        # Default: final answer
        return {
            "action_type": "final_answer",
            "response": self._synthesize_final_report(
                user_input=user_input,
                system_prompt="",
                conversation_context=conversation_context,
                findings=findings,
            ),
        }

    def _llm_recovery_decision(
        self,
        user_input: str,
        system_prompt: str,
        conversation_context: str,
        failed_tool: str,
        failed_args: dict,
        failed_output: str,
    ) -> Optional[Dict[str, Any]]:
        """Asks LLM for a recovery strategy when a tool fails."""
        prompt = f"""
A tool failed during investigation. Please suggest an alternative approach.

User objective: {user_input}
Failed tool: {failed_tool}
Failed arguments: {json.dumps(failed_args)}
Error/output: {failed_output[:500]}

Available tools: {json.dumps([getattr(t, 'name', getattr(t, 'tool_name', str(t))) for t in getattr(self.agent.registry, "tools", {}).values()])}

Suggest an alternative tool or approach. Return JSON:
{{
  "action_type": "tool",
  "tool_name": "alternative_tool",
  "arguments": {{}},
  "brief": "recovery: trying alternative approach",
  "reason": "previous tool failed, trying different approach",
  "is_recovery": true
}}
"""
        try:
            response = self._call_llm(system=system_prompt, user=prompt)
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                decision = json.loads(json_match.group(0))
                if decision.get("action_type") == "tool":
                    tool_name = decision.get("tool_name")
                    if tool_name in getattr(self.agent.registry, "tools", {}):
                        if not decision.get("arguments"):
                            decision["arguments"] = self._build_tool_args(tool_name, user_input)
                        return decision
        except Exception:
            pass
        return None

    def _build_tool_args(self, tool_name: str, user_input: str) -> Dict[str, Any]:
        """Build arguments for a tool based on user input."""
        import re
        args = {}
        
        if tool_name == "web_search":
            # Extract search query from user input
            query = self._extract_search_query(user_input)
            args["query"] = query
        
        elif tool_name == "open_url":
            # Extract URL from user input or context
            url = self._extract_url(user_input)
            if not url:
                # Try to find URL in recent context
                url = "https://example.com"
            args["url"] = url
        
        elif tool_name == "network_inspect":
            args = {}
        
        elif tool_name == "windows_defender_scan":
            if hasattr(self.agent, "_extract_scan_target"):
                args["path"] = self.agent._extract_scan_target(user_input)
            else:
                args["path"] = "."
        
        elif tool_name == "static_analysis":
            args["filepath"] = "ideas/code 1"
        
        elif tool_name == "file_tool":
            args = {"action": "read", "path": "test_output.txt"}
        
        elif tool_name == "notes":
            args = {"action": "create", "title": "Investigation Note", "content": user_input}
        
        elif tool_name == "todo_write":
            args = {"todos": [{"id": "1", "text": user_input, "status": "in_progress"}]}
        
        return args

    def _extract_search_query(self, user_input: str) -> str:
        """Extract a search query from user input."""
        import re
        # Remove common prefixes
        query = user_input
        for prefix in ["search for", "research", "look up", "find", "browse", "what is", "how to", "latest", "version"]:
            if query.lower().startswith(prefix):
                query = query[len(prefix):].strip()
        # Use first sentence or first 100 chars
        query = query.split(".")[0][:100]
        return query.strip()

    def _extract_url(self, user_input: str) -> str:
        """Extract URL from user input."""
        import re
        urls = re.findall(r'https?://[^\s<>"\]]+', user_input)
        return urls[0] if urls else ""

    def _extract_url_from_context(self, context: str) -> str:
        """Extract URL from conversation context."""
        import re
        urls = re.findall(r'https?://[^\s<>"\]]+', context)
        return urls[-1] if urls else "https://example.com"

    def _is_result_sufficient(self, tool_name: str, output: str, step_idx: int) -> bool:
        """Evaluate if a tool's output is sufficient to answer the user's question."""
        if not output or len(output.strip()) < 50:
            return False
        
        # Tool-specific sufficiency checks
        if tool_name == "web_search":
            # Check if search returned results
            if "results" in output.lower() or "found" in output.lower():
                return True
            return len(output) > 200
        
        if tool_name == "open_url":
            # Check if page content was extracted
            if len(output) > 500:
                return True
            return False
        
        if tool_name in ("network_inspect", "windows_defender_scan", "static_analysis"):
            # These tools should have substantial output
            return len(output) > 100
        
        # Default: consider sufficient if output is substantial
        return len(output) > 100

    def _call_llm(self, system: str, user: str) -> str:
        """Helper to invoke configured AI backend."""
        try:
            # Try orchestrator's _call_role with investigator role
            if hasattr(self.agent, "orchestrator") and hasattr(self.agent.orchestrator, "_call_role"):
                return self.agent.orchestrator._call_role("investigator", system, user)
            # Fallback: try LLMClient from tool_orchestrator
            if hasattr(self.agent, "orchestrator") and hasattr(self.agent.orchestrator, "llm"):
                llm = self.agent.orchestrator.llm
                if hasattr(llm, "chat_with_role"):
                    return llm.chat_with_role("investigator", system, user)
                elif hasattr(llm, "chat"):
                    return llm.chat(system=system, user=user, role="investigator")
        except Exception as e:
            print(f"[AgentRuntime] LLM call failed: {e}")
        return "AI provider unavailable. Configure the selected provider to generate the investigation report."

    def _synthesize_final_report(
        self,
        user_input: str,
        system_prompt: str,
        conversation_context: str,
        findings: List[Dict[str, Any]],
    ) -> str:
        """Synthesizes structured findings into an executive report."""
        findings_summary = f"{len(findings)} security finding(s) detected." if findings else "No immediate high-severity threats detected."
        prompt = (
            f"User Objective: {user_input}\n\n"
            f"Investigation History:\n{conversation_context[-6000:]}\n\n"
            f"Findings Status: {findings_summary}\n\n"
            "Provide a clear, structured investigation report containing:\n"
            "1. Executive Summary\n"
            "2. Telemetry & Observations (with evidence)\n"
            "3. Findings & Severity\n"
            "4. Recommended Next Actions"
        )
        return self._call_llm(system=system_prompt, user=prompt)
