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

import difflib
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cyber_os.approval_engine import ApprovalEngine
from cyber_os.assets import paths
from cyber_os.compaction import ContextCompactor, estimate_tokens
from cyber_os.doom_loop_detector import DoomLoopDetector, DoomLoopSeverity
from cyber_os.pty_session_manager import PtySessionManager
from cyber_os.stop_conditions import FinishReason, StopConditions
from cyber_os.subagents.manager import SubagentManager
from cyber_os.system_prompt import SystemPromptComposer
from ui.event_bus import AgentEvent, event_bus

# Per-step render cap. The compactor enforces the aggregate budget by replacing
# older outputs with placeholders; this stops any single step from dominating
# the prompt before that happens.
STEP_RENDER_CHARS = 2000

# Stored per step, before pruning. Larger than the render cap so a step the
# model is still working with keeps enough detail to be re-read.
STEP_STORE_CHARS = 8000

DEFAULT_MAX_STEPS = 15
DEFAULT_MAX_ELAPSED_SECONDS = 300.0


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


@dataclass
class _RunState:
    """State for one investigation.

    ``AgentRuntime`` is a singleton on ``CyberAgent``, so the step budget and
    loop-detection history must not live on the runtime: two overlapping
    investigations would share one set of counters.
    """

    investigation_id: str
    session_id: str
    user_input: str
    cancel_event: threading.Event
    stop_conditions: StopConditions
    doom_loop_detector: DoomLoopDetector
    steps_record: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    notices: List[str] = field(default_factory=list)
    pending_recovery: Optional[Dict[str, Any]] = None
    recovered_tools: set = field(default_factory=set)
    # tool name the model asked for -> how many times it was not registered
    rejected_tools: Dict[str, int] = field(default_factory=dict)


class AgentRuntime:
    """The central SVS-Cyber agent runtime engine."""

    def __init__(self, agent: Any) -> None:
        self.agent = agent
        self.compactor = ContextCompactor()
        self.pty_manager = PtySessionManager.get_instance()
        self.approval_engine = ApprovalEngine()
        self.subagent_manager = SubagentManager(agent)
        self.max_steps = DEFAULT_MAX_STEPS
        self.max_elapsed_seconds = DEFAULT_MAX_ELAPSED_SECONDS
        self._active_runs: Dict[str, _RunState] = {}
        self._lock = threading.Lock()

    # --- Run control ----------------------------------------------------

    def cancel_run(self, investigation_id: str) -> bool:
        """Cancel one in-flight investigation. Returns True if it was running.

        Targets a single run, unlike the agent-level ``cancel_event``, which
        stops every investigation the agent is currently executing.
        """
        with self._lock:
            state = self._active_runs.get(investigation_id)
        if state is None:
            return False
        state.cancel_event.set()
        return True

    def active_run_ids(self) -> List[str]:
        with self._lock:
            return list(self._active_runs)

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

        # The agent-level event is what ui/api_server.py signals, so it stays the
        # primary cancel channel. Only cleared when no other run is in flight —
        # clearing it unconditionally would revoke a cancellation just requested
        # for a concurrent investigation.
        agent_cancel = getattr(self.agent, "cancel_event", None)
        if agent_cancel is not None and not self._active_runs:
            agent_cancel.clear()

        state = _RunState(
            investigation_id=inv_id,
            session_id=session_id,
            user_input=user_input,
            cancel_event=threading.Event(),
            stop_conditions=StopConditions(
                max_steps=self.max_steps,
                max_elapsed_seconds=self.max_elapsed_seconds,
            ),
            doom_loop_detector=DoomLoopDetector(),
        )

        with self._lock:
            self._active_runs[inv_id] = state

        def is_cancelled() -> bool:
            if state.cancel_event.is_set():
                return True
            return agent_cancel is not None and agent_cancel.is_set()

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

        final_response = ""
        response_published = False

        try:
            while not state.stop_conditions.should_stop(is_cancelled=is_cancelled()):
                step_idx = state.stop_conditions.steps_executed + 1

                if is_cancelled():
                    final_response = self._mark_cancelled(state)
                    break

                # A. Prepare Step: prune older tool outputs before rendering the
                #    prompt, so pruning actually shrinks what the model receives.
                prune_result = self.compactor.prune_tool_steps(state.steps_record)
                if prune_result.pruned_count > 0:
                    state.steps_record = prune_result.steps

                conversation_context = self._render_context(state)

                # B. Determine Next Action using Live Model or Specialist Heuristics
                step_decision = self._decide_next_step(
                    state=state,
                    system_prompt=system_prompt,
                    conversation_context=conversation_context,
                    step_index=step_idx,
                )

                action_type = step_decision.get("action_type")  # 'tool', 'subagent', 'final_answer'

                # --- Path 1: Final Answer ---
                if action_type == "final_answer":
                    final_response = step_decision.get("response") or ""
                    if not final_response.strip():
                        # The decider concluded without composing an answer
                        # (heuristic fallback, or a forced stop). Synthesize from
                        # the evidence rather than publishing an empty message.
                        final_response = self._synthesize_final_report(
                            user_input=user_input,
                            system_prompt=system_prompt,
                            conversation_context=conversation_context,
                            findings=state.findings,
                        )
                    self.publish_activity(session_id, inv_id, "Synthesizing final answer...", "running")
                    state.stop_conditions.record_step(tokens_used=estimate_tokens(final_response))

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
                    state.stop_conditions.record_step(
                        tokens_used=estimate_tokens(subagent_result.summary)
                    )

                    state.steps_record.append({
                        "step": step_idx,
                        "type": "subagent",
                        "profile": subagent_result.profile,
                        "objective": subagent_objective,
                        "verdict": subagent_result.verdict.value,
                        "confidence": subagent_result.confidence.value,
                        "output": subagent_result.summary,
                    })

                    # A delegation that resolved to no real specialist must not
                    # look like a completed one, or the model treats the failure
                    # notice as an analytical result.
                    if subagent_result.error:
                        state.notices.append(
                            f"Delegation to '{subagent_profile}' failed: {subagent_result.error} "
                            "Use agent_definition_search to find a valid specialist, or continue directly."
                        )

                    if subagent_result.findings:
                        state.findings.extend(subagent_result.findings)

                # --- Path 3: Tool Execution ---
                elif action_type == "tool":
                    tool_name = step_decision.get("tool_name", "")
                    tool_args = step_decision.get("arguments", {})
                    brief = step_decision.get("brief", f"Executing {tool_name}")

                    # Check for cancellation before executing
                    if is_cancelled():
                        final_response = self._mark_cancelled(state)
                        break

                    # Doom loop detection check
                    loop_eval = state.doom_loop_detector.record_step(tool_name, tool_args)
                    if loop_eval.severity == DoomLoopSeverity.HALT:
                        state.stop_conditions.should_stop(doom_loop_halt=True)
                        halt_note = loop_eval.nudge_message or "Investigation halted due to repetitive loop."
                        state.notices.append(halt_note)
                        self.publish_activity(session_id, inv_id, "Investigation halted: doom loop detected", "error")
                        event_bus.publish(
                            AgentEvent(
                                type="agent_error",
                                status="error",
                                message=halt_note,
                                session_id=session_id,
                                investigation_id=inv_id,
                                source="agent_runtime",
                                data={"reason": "doom_loop_detected"},
                            )
                        )
                        # Report on the evidence already gathered rather than
                        # handing the user the loop-detector's own message as if
                        # it were the investigation's answer.
                        final_response = self._synthesize_final_report(
                            user_input=user_input,
                            system_prompt=system_prompt,
                            conversation_context=self._render_context(state),
                            findings=state.findings,
                        )
                        break
                    elif loop_eval.severity == DoomLoopSeverity.WARNING:
                        state.notices.append(loop_eval.nudge_message or "")
                        self.publish_activity(session_id, inv_id, loop_eval.nudge_message, "running")

                    # Publish agent_reasoning for the decision (execute_tool will publish tool_started/completed)
                    self.publish_activity(session_id, inv_id, brief or f"Decided to use {tool_name}", "running")

                    # Execute tool via CyberAgent (which publishes tool_started/completed/failed/cancelled events)
                    exec_result = self.agent.execute_tool(tool_name, tool_args)
                    tool_success = exec_result.get("success", False)
                    error = exec_result.get("error")
                    raw_out = str(exec_result.get("output") or error or "")

                    screenshot_path = self._capture_browser_screenshot(tool_name, tool_success, step_idx)

                    # Bounded output truncation for context safety
                    trimmed_out = raw_out[:STEP_STORE_CHARS]
                    state.stop_conditions.record_step(tokens_used=estimate_tokens(trimmed_out))

                    step_entry: Dict[str, Any] = {
                        "step": step_idx,
                        "tool": tool_name,
                        "arguments": tool_args,
                        "success": tool_success,
                        "output": trimmed_out,
                    }
                    if screenshot_path:
                        step_entry["screenshot"] = screenshot_path
                    state.steps_record.append(step_entry)

                    # Publish agent_reasoning for analyzing results
                    if tool_success:
                        self.publish_activity(session_id, inv_id, f"Analyzing {tool_name} results...", "running")
                    elif error:
                        self.publish_activity(session_id, inv_id, f"{tool_name} failed: {error[:200]}", "error")

                    # Check if tool result is sufficient, queue recovery if not.
                    if (
                        tool_success
                        and tool_name not in state.recovered_tools
                        and not self._is_result_sufficient(tool_name, trimmed_out, step_idx)
                    ):
                        state.recovered_tools.add(tool_name)
                        recovery = self._llm_recovery_decision(
                            state=state,
                            system_prompt=system_prompt,
                            conversation_context=self._render_context(state),
                            failed_tool=tool_name,
                            failed_args=tool_args,
                            failed_output=f"Result may be insufficient: {trimmed_out[:300]}",
                        )
                        if recovery:
                            # Consumed by _decide_next_step on the next iteration.
                            state.pending_recovery = recovery
                            state.notices.append(
                                f"Result from {tool_name} looked thin; trying an alternative approach."
                            )
                            self.publish_activity(
                                session_id, inv_id,
                                f"Recovery: trying alternative approach for {tool_name}",
                                "running",
                            )

                    finding = self._finding_from_result(tool_name, exec_result, raw_out)
                    if finding is not None:
                        state.findings.append(finding)
                        event_bus.publish(
                            AgentEvent(
                                type="finding_created",
                                status="created",
                                message=finding["title"],
                                session_id=session_id,
                                investigation_id=inv_id,
                                source="agent_runtime",
                                data=finding,
                            )
                        )

                else:
                    # Default: complete
                    break

        except Exception as exc:
            final_response = f"Investigation encountered an unexpected error: {exc}"
            state.stop_conditions.finish_reason = FinishReason.ERROR
            state.stop_conditions.finish_message = str(exc)
            # Lets the UI distinguish a failed investigation from a completed
            # one; a plain response event carries no such signal.
            event_bus.publish(
                AgentEvent(
                    type="agent_error",
                    status="error",
                    message=final_response,
                    session_id=session_id,
                    investigation_id=inv_id,
                    source="agent_runtime",
                    data={"reason": "exception", "error": str(exc)},
                )
            )

        if not final_response:
            if state.stop_conditions.finish_reason is FinishReason.USER_CANCELLED:
                # should_stop() sets USER_CANCELLED when the loop is cancelled
                # before its first iteration, so _mark_cancelled never ran.
                # Synthesizing a report here would bill an LLM call for a run
                # the user just stopped.
                final_response = self._mark_cancelled(state)
            else:
                final_response = self._synthesize_final_report(
                    user_input=user_input,
                    system_prompt=system_prompt,
                    conversation_context=self._render_context(state),
                    findings=state.findings,
                )

        duration = time.time() - start_time
        finish_reason_val = (
            state.stop_conditions.finish_reason.value
            if state.stop_conditions.finish_reason
            else FinishReason.COMPLETE.value
        )

        event_bus.publish(
            AgentEvent(
                type="investigation_completed",
                status="completed" if finish_reason_val == FinishReason.COMPLETE.value else "finished",
                message=f"Investigation completed: {len(state.findings)} finding(s)",
                session_id=session_id,
                investigation_id=inv_id,
                source="agent_runtime",
                data={
                    "investigation_id": inv_id,
                    "findings_count": len(state.findings),
                    "finish_reason": finish_reason_val,
                    "duration_seconds": round(duration, 2),
                },
            )
        )

        # If final response was synthesized (not published via the final_answer
        # action path above), publish a response event now so the frontend
        # renders it. The cancelled comparison used the literal "cancelled",
        # which FinishReason never produces, so a cancelled run published a
        # response event on top of its agent_cancelled event.
        if not response_published and finish_reason_val != FinishReason.USER_CANCELLED.value:
            event_bus.publish(
                AgentEvent(
                    type="response",
                    status="completed" if finish_reason_val == FinishReason.COMPLETE.value else "error",
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
            success=finish_reason_val == FinishReason.COMPLETE.value,
            response=final_response,
            investigation_id=inv_id,
            session_id=session_id,
            steps_executed=state.stop_conditions.steps_executed,
            findings=state.findings,
            finish_reason=finish_reason_val,
            finish_message=state.stop_conditions.finish_message or "Complete",
            duration_seconds=duration,
        )

    # --- Loop helpers ---------------------------------------------------

    def _mark_cancelled(self, state: _RunState) -> str:
        """Record and announce a cancellation.

        The enum member is ``USER_CANCELLED``; ``FinishReason`` has no
        ``CANCELLED``. Assigning the wrong name here raises into the loop's own
        exception handler and reports the cancellation as an unexpected error.
        """
        state.stop_conditions.finish_reason = FinishReason.USER_CANCELLED
        state.stop_conditions.finish_message = "Cancelled by user"
        event_bus.publish(
            AgentEvent(
                type="agent_cancelled",
                status="cancelled",
                message="Investigation was cancelled by user",
                session_id=state.session_id,
                investigation_id=state.investigation_id,
                source="agent_runtime",
            )
        )
        return "Investigation was cancelled by user."

    def _render_context(self, state: _RunState) -> str:
        """Build the model-facing transcript from the current step record.

        Rendering from the record every iteration is what makes the compactor's
        token budget real: pruning rewrites the record, so the next prompt
        shrinks with it. A separately accumulated context string would keep the
        pruned text alive and send each tool output twice.
        """
        lines = [f"User Request: {state.user_input}"]

        for step in state.steps_record:
            output = str(step.get("output") or "")
            if len(output) > STEP_RENDER_CHARS:
                output = output[:STEP_RENDER_CHARS] + "... [truncated]"

            if step.get("type") == "subagent":
                lines.append(
                    f"\n[Subagent '{step.get('profile')}' Result]: "
                    f"Verdict: {step.get('verdict')} (Confidence: {step.get('confidence')})\n"
                    f"{output}"
                )
            elif "tool" in step:
                lines.append(
                    f"\n[Tool '{step.get('tool')}' Result "
                    f"(Success={step.get('success')})]:\n{output}"
                )

        # Only the most recent notices: they are corrective nudges, and a stale
        # one repeated every render would outlive the situation it described.
        for notice in state.notices[-5:]:
            if notice:
                lines.append(f"\n[System Notice]: {notice}")

        return "\n".join(lines) + "\n"

    def _capture_browser_screenshot(
        self, tool_name: str, tool_success: bool, step_idx: int
    ) -> Optional[str]:
        """Capture a page screenshot after a browser tool, if one is available."""
        if not tool_success or tool_name not in ("web_search", "open_url"):
            return None
        try:
            from Tools_cyber.browser_manager import BrowserManager

            manager = BrowserManager.get_instance()
            page = getattr(manager, "page", None)
            if page is None:
                return None
            # Was hardcoded to an absolute D:/ path, which broke the capture on
            # any other checkout. Resolves from the project root instead.
            shots_dir = paths.project_root() / ".stai"
            shots_dir.mkdir(parents=True, exist_ok=True)
            target = shots_dir / f"agent_{tool_name}_{step_idx}_{int(time.time())}.png"
            page.screenshot(path=str(target))
            return str(target)
        except Exception as exc:
            print(f"[AgentRuntime] Screenshot capture failed: {exc}")
            return None

    @staticmethod
    def _finding_from_result(
        tool_name: str, exec_result: Dict[str, Any], raw_out: str
    ) -> Optional[Dict[str, Any]]:
        """Build a finding only when the tool actually reported one.

        Matching on output text instead — e.g. the substring "threat" — mints
        findings the agent never made, from a threat-intel search's own results
        or a tool's help text.
        """
        reported = exec_result.get("finding") or exec_result.get("findings")
        if not reported:
            return None

        if isinstance(reported, list):
            if not reported:
                return None
            first = reported[0]
            detail = first if isinstance(first, dict) else {"evidence": str(first)}
        elif isinstance(reported, dict):
            detail = reported
        else:
            detail = {"evidence": str(reported)}

        return {
            "id": f"find_{uuid.uuid4().hex[:6]}",
            "tool": tool_name,
            "title": detail.get("title") or f"Finding from {tool_name}",
            "severity": detail.get("severity", "medium"),
            "evidence": str(detail.get("evidence") or raw_out)[:300],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

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

    def _registered_tool_names(self) -> List[str]:
        """Names the agent will actually accept in ``execute_tool``."""
        try:
            return sorted(getattr(self.agent.registry, "tools", {}).keys())
        except Exception as exc:
            print(f"[AgentRuntime] Failed to read tool registry: {exc}")
            return []

    def _decide_next_step(
        self,
        state: _RunState,
        system_prompt: str,
        conversation_context: str,
        step_index: int,
    ) -> Dict[str, Any]:
        """Decides the next action (tool, subagent, or final answer)."""
        # A recovery plan queued at the end of the previous step runs now, and
        # pre-empts asking the model for a fresh decision.
        if state.pending_recovery is not None:
            recovery = state.pending_recovery
            state.pending_recovery = None
            return recovery

        decision = self._llm_decide_action(
            state=state,
            system_prompt=system_prompt,
            conversation_context=conversation_context,
            step_index=step_index,
        )

        # Recovery after an outright tool failure. Capped at one attempt per
        # tool so a persistently broken tool cannot burn the whole step budget
        # on recovery planning.
        if step_index > 1 and state.steps_record and not decision.get("is_recovery"):
            last_step = state.steps_record[-1]
            failed_tool = last_step.get("tool")
            if (
                last_step.get("success") is False
                and failed_tool
                and failed_tool not in state.recovered_tools
            ):
                state.recovered_tools.add(failed_tool)
                recovery_decision = self._llm_recovery_decision(
                    state=state,
                    system_prompt=system_prompt,
                    conversation_context=conversation_context,
                    failed_tool=failed_tool,
                    failed_args=last_step.get("arguments") or {},
                    failed_output=str(last_step.get("output") or ""),
                )
                if recovery_decision:
                    return recovery_decision

        return decision

    def _llm_decide_action(
        self,
        state: _RunState,
        system_prompt: str,
        conversation_context: str,
        step_index: int,
    ) -> Dict[str, Any]:
        """Uses the model to decide the next action."""
        tool_names = self._registered_tool_names()

        # ``conversation_context`` already carries every prior step, rendered
        # from the pruned record, so no second step summary is appended here.
        prompt = f"""
{conversation_context}

Available tools: {json.dumps(tool_names)}

You are SVS-Cyber, an autonomous cybersecurity investigation agent.
Current step: {step_index}
User objective: {state.user_input}

Based on the conversation history and available tools, decide the next action.
Use only a tool name from the list above — any other name will be rejected.

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
            json_match = re.search(r'\{.*\}', response, re.DOTALL) if response else None
            if json_match:
                decision = json.loads(json_match.group(0))

                if decision.get("action_type") == "tool":
                    tool_name = decision.get("tool_name")
                    registry = getattr(self.agent.registry, "tools", {})
                    if tool_name and tool_name in registry:
                        if not decision.get("arguments"):
                            decision["arguments"] = self._build_tool_args(
                                tool_name, state.user_input
                            )
                        return decision

                    # Tell the model the name was wrong. Discarding it silently
                    # means it re-proposes the same missing tool every step, and
                    # the doom-loop detector never sees it — that only records
                    # tools that actually executed.
                    escalation = self._reject_unknown_tool(state, tool_name, tool_names)
                    if escalation is not None:
                        return escalation
                elif decision.get("action_type") in ("subagent", "final_answer"):
                    return decision
        except Exception as e:
            print(f"[AgentRuntime] LLM decision failed: {e}")

        # Fallback to heuristic-based decision
        return self._heuristic_decide_action(
            state=state,
            conversation_context=conversation_context,
            step_index=step_index,
        )

    def _reject_unknown_tool(
        self, state: _RunState, tool_name: Optional[str], tool_names: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Feed an unregistered tool name back to the model.

        Returns a forced final-answer decision once the same bad name has been
        proposed three times, so a model fixated on a tool that does not exist
        cannot spin until the step limit.
        """
        label = tool_name or "<missing>"
        count = state.rejected_tools.get(label, 0) + 1
        state.rejected_tools[label] = count

        if count >= 3:
            state.notices.append(
                f"Tool '{label}' does not exist and was requested {count} times. "
                "Concluding with the evidence gathered so far."
            )
            return {
                "action_type": "final_answer",
                "response": "",
                "reason": f"repeatedly requested unavailable tool '{label}'",
            }

        suggestions = self._suggest_tool_names(label, tool_names)
        notice = f"Tool '{label}' is not available in this deployment."
        if suggestions:
            notice += f" Closest available names: {', '.join(suggestions)}."
        notice += " Pick a tool from the available list or answer directly."
        state.notices.append(notice)
        return None

    @staticmethod
    def _suggest_tool_names(requested: str, tool_names: List[str], limit: int = 3) -> List[str]:
        """Nearest registered names for a rejected tool name."""
        if not requested or not tool_names:
            return []
        return difflib.get_close_matches(requested, tool_names, n=limit, cutoff=0.5)

    def _heuristic_decide_action(
        self,
        state: _RunState,
        conversation_context: str,
        step_index: int,
    ) -> Dict[str, Any]:
        """Fallback heuristic decision (keyword-based) when the model is unusable."""
        user_input = state.user_input
        lower = user_input.lower()
        executed_tools = {s.get("tool") for s in state.steps_record if "tool" in s}

        # Web research triggers
        if any(w in lower for w in ("search", "research", "look up", "find", "browse", "web", "documentation", "docs", "latest", "version")):
            if "web_search" not in executed_tools:
                return {
                    "action_type": "tool",
                    "tool_name": "web_search",
                    "arguments": {"query": self._extract_search_query(user_input)},
                    "brief": "Searching the web for relevant information",
                }
            # Only follow a URL that actually appeared in the request or in a
            # tool result; a placeholder would produce a confident-looking step
            # with no bearing on the task.
            if "open_url" not in executed_tools:
                url = self._extract_url(user_input) or self._extract_url_from_context(conversation_context)
                if url:
                    return {
                        "action_type": "tool",
                        "tool_name": "open_url",
                        "arguments": {"url": url},
                        "brief": f"Opening {url} for detailed information",
                    }

        # Network investigation
        if any(w in lower for w in ("network", "port", "connection", "listening")) and "network_inspect" not in executed_tools:
            return {"action_type": "tool", "tool_name": "network_inspect", "arguments": {}, "brief": "Inspecting active network connections and listening sockets"}

        # Malware / File investigation
        if any(w in lower for w in ("malware", "virus", "defender", "download")) and "windows_defender_scan" not in executed_tools:
            scan_target = self.agent._extract_scan_target(user_input) if hasattr(self.agent, "_extract_scan_target") else "."
            return {"action_type": "tool", "tool_name": "windows_defender_scan", "arguments": {"path": scan_target}, "brief": f"Running Windows Defender scan on '{scan_target}'"}

        # Code / SAST analysis. Skipped unless the request names a real target:
        # a default path would analyze a file nobody asked about.
        if any(w in lower for w in ("code", "sast", "source", "script")) and "static_analysis" not in executed_tools:
            target = self._extract_path(user_input)
            if target:
                return {
                    "action_type": "tool",
                    "tool_name": "static_analysis",
                    "arguments": {"filepath": target},
                    "brief": f"Analyzing '{target}' for security vulnerabilities",
                }

        # Subagent delegation
        executed_subagents = {s.get("profile") for s in state.steps_record if s.get("type") == "subagent"}
        if ("threat" in lower or "ioc" in lower) and "threat_analysis" not in executed_subagents:
            return {"action_type": "subagent", "profile": "threat_analysis", "objective": f"Analyze threat indicators for: {user_input}"}

        # Note taking
        if any(w in lower for w in ("note", "record", "remember")) and "notes" not in executed_tools:
            return {"action_type": "tool", "tool_name": "notes", "arguments": {"action": "create", "title": "Investigation Note", "content": user_input}, "brief": "Creating investigation note"}

        # Todo tracking
        if any(w in lower for w in ("todo", "task", "plan", "track")) and "todo_write" not in executed_tools:
            return {"action_type": "tool", "tool_name": "todo_write", "arguments": {"todos": [{"id": "1", "text": user_input, "status": "in_progress"}]}, "brief": "Creating investigation task list"}

        # Default: let run_investigation synthesize the report from the same
        # rendered context, instead of synthesizing a second one here.
        return {"action_type": "final_answer", "response": ""}

    def _llm_recovery_decision(
        self,
        state: _RunState,
        system_prompt: str,
        conversation_context: str,
        failed_tool: str,
        failed_args: dict,
        failed_output: str,
    ) -> Optional[Dict[str, Any]]:
        """Asks the model for a recovery strategy when a tool fails or underdelivers."""
        prompt = f"""
A tool failed during investigation. Please suggest an alternative approach.

User objective: {state.user_input}
Failed tool: {failed_tool}
Failed arguments: {json.dumps(failed_args)}
Error/output: {str(failed_output)[:500]}

Available tools: {json.dumps(self._registered_tool_names())}

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
            if not response:
                return None
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                decision = json.loads(json_match.group(0))
                if decision.get("action_type") == "tool":
                    tool_name = decision.get("tool_name")
                    # A recovery that re-proposes the tool that just failed is
                    # not a recovery.
                    if tool_name == failed_tool:
                        return None
                    if tool_name in getattr(self.agent.registry, "tools", {}):
                        if not decision.get("arguments"):
                            decision["arguments"] = self._build_tool_args(
                                tool_name, state.user_input
                            )
                        decision["is_recovery"] = True
                        return decision
        except Exception:
            pass
        return None

    def _build_tool_args(self, tool_name: str, user_input: str) -> Dict[str, Any]:
        """Build arguments for a tool based on user input."""
        args: Dict[str, Any] = {}

        if tool_name == "web_search":
            args["query"] = self._extract_search_query(user_input)

        elif tool_name == "open_url":
            # No placeholder fallback: without a real URL the caller gets empty
            # args and the tool reports the missing argument itself.
            url = self._extract_url(user_input)
            if url:
                args["url"] = url

        elif tool_name == "network_inspect":
            args = {}

        elif tool_name == "windows_defender_scan":
            if hasattr(self.agent, "_extract_scan_target"):
                args["path"] = self.agent._extract_scan_target(user_input)
            else:
                args["path"] = "."

        elif tool_name == "static_analysis":
            target = self._extract_path(user_input)
            if target:
                args["filepath"] = target

        elif tool_name == "notes":
            args = {"action": "create", "title": "Investigation Note", "content": user_input}

        elif tool_name == "todo_write":
            args = {"todos": [{"id": "1", "text": user_input, "status": "in_progress"}]}

        return args

    def _extract_search_query(self, user_input: str) -> str:
        """Extract a search query from user input."""
        query = user_input
        for prefix in ["search for", "research", "look up", "find", "browse", "what is", "how to", "latest", "version"]:
            if query.lower().startswith(prefix):
                query = query[len(prefix):].strip()
        query = query.split(".")[0][:100]
        return query.strip()

    def _extract_url(self, user_input: str) -> str:
        """Extract URL from user input."""
        urls = re.findall(r'https?://[^\s<>"\]]+', user_input)
        return urls[0] if urls else ""

    def _extract_url_from_context(self, context: str) -> str:
        """Extract the most recent URL seen in the rendered transcript."""
        urls = re.findall(r'https?://[^\s<>"\]]+', context)
        return urls[-1] if urls else ""

    @staticmethod
    def _extract_path(user_input: str) -> str:
        """Extract a file or directory path mentioned in the request."""
        match = re.search(
            r"[\w./\\-]+\.(?:py|js|ts|tsx|jsx|go|rs|java|rb|php|cs|cpp|c|md|json|ya?ml|txt|log|ini|cfg|exe|dll|ps1|sh|bat)",
            user_input,
        )
        if match:
            return match.group(0)
        quoted = re.search(r"['\"]([^'\"]{2,120})['\"]", user_input)
        if quoted:
            return quoted.group(1)
        return ""

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

    def _call_llm(self, system: str, user: str) -> Optional[str]:
        """Invoke the configured AI backend, or return None if there isn't one.

        None rather than an apology string: the string form used to be returned
        to every caller, so an unreachable provider silently became the
        investigation's final report — discarding whatever the tools had
        already found. Callers must decide what an absent model means for them.
        """
        orchestrator = getattr(self.agent, "orchestrator", None)
        if orchestrator is None:
            return None
        try:
            if hasattr(orchestrator, "_call_role"):
                return orchestrator._call_role("investigator", system, user)
            llm = getattr(orchestrator, "llm", None)
            if llm is None:
                return None
            if hasattr(llm, "chat_with_role"):
                return llm.chat_with_role("investigator", system, user)
            if hasattr(llm, "chat"):
                return llm.chat(system=system, user=user, role="investigator")
        except Exception as exc:
            print(f"[AgentRuntime] LLM call failed: {exc}")
        return None

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
        report = self._call_llm(system=system_prompt, user=prompt)
        if report and report.strip():
            return report
        return self._offline_report(user_input, conversation_context, findings)

    @staticmethod
    def _offline_report(
        user_input: str,
        conversation_context: str,
        findings: List[Dict[str, Any]],
    ) -> str:
        """Report the collected evidence without a model.

        The tools ran and their output is already in hand; with no provider
        reachable the only thing missing is the prose. Returning a bare
        "provider unavailable" line instead would throw that evidence away and
        leave the user unable to tell a clean result from a failed run.
        """
        lines = [
            "### Investigation Report (offline)",
            "",
            f"**Objective:** {user_input}",
            "",
            "_No AI provider was reachable, so this report is the raw evidence "
            "the tools returned, without model analysis. Configure a provider "
            "for a written assessment._",
            "",
        ]

        if findings:
            lines.append(f"**Findings ({len(findings)}):**")
            for finding in findings:
                severity = str(finding.get("severity") or "unknown").upper()
                title = finding.get("title") or finding.get("tool") or "finding"
                lines.append(f"- [{severity}] {title}")
                evidence = str(finding.get("evidence") or "").strip()
                if evidence:
                    lines.append(f"  - evidence: {evidence[:400]}")
        else:
            lines.append("**Findings:** none reported by the tools that ran.")

        lines.extend(["", "**Collected evidence:**", "", "```text",
                      conversation_context[-4000:].strip() or "(no tool output recorded)", "```"])
        return "\n".join(lines)
