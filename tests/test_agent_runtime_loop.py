"""
tests/test_agent_runtime_loop.py — behaviour of the multi-step agent loop.

Covers the loop's control flow rather than its prompts: cancellation, real
context pruning, recovery hand-off, rejection of unregistered tools, finding
attribution, and per-run state isolation. The runtime accepts any object as its
``agent``, so these drive it with a stub instead of a full ``CyberAgent``.
"""

from __future__ import annotations

import os
import sys
import threading
import unittest
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_os.agent_runtime import (  # noqa: E402
    STEP_RENDER_CHARS,
    AgentRuntime,
    _RunState,
)
from cyber_os.doom_loop_detector import DoomLoopDetector  # noqa: E402
from cyber_os.stop_conditions import FinishReason, StopConditions  # noqa: E402
from ui.event_bus import AgentEvent, event_bus  # noqa: E402


class _StubRegistry:
    def __init__(self, tool_names: List[str]) -> None:
        self.tools = {name: _StubTool(name) for name in tool_names}


class _StubTool:
    def __init__(self, name: str) -> None:
        self.name = name

    def to_manifest(self) -> Dict[str, Any]:
        return {"name": self.name, "description": f"stub {self.name}"}


class _StubAgent:
    """Minimal stand-in for CyberAgent.

    ``decisions`` is the queue the stubbed LLM hands back, one per call;
    ``tool_results`` maps a tool name to the dict ``execute_tool`` returns.
    """

    def __init__(
        self,
        tool_names: Optional[List[str]] = None,
        tool_results: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self.registry = _StubRegistry(tool_names or ["network_inspect", "web_search"])
        self.workspace_path = "."
        self.cancel_event = threading.Event()
        self.tool_results = tool_results or {}
        self.executed: List[str] = []

    def execute_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        self.executed.append(name)
        return self.tool_results.get(name, {"success": True, "output": "stub output " * 40})


class _EventRecorder:
    """Captures everything published while a run is in flight."""

    def __init__(self) -> None:
        self.events: List[AgentEvent] = []
        event_bus.subscribe_all(self._on_event)

    def _on_event(self, event: AgentEvent) -> None:
        self.events.append(event)

    def detach(self) -> None:
        with event_bus._lock:  # no public unsubscribe_all exists
            event_bus._global_listeners = [
                cb for cb in event_bus._global_listeners if cb != self._on_event
            ]

    def types(self) -> List[str]:
        return [e.type for e in self.events]


def _make_state(runtime: AgentRuntime, user_input: str = "check the network") -> _RunState:
    return _RunState(
        investigation_id="inv_test",
        session_id="sess_test",
        user_input=user_input,
        cancel_event=threading.Event(),
        stop_conditions=StopConditions(max_steps=5, max_elapsed_seconds=30.0),
        doom_loop_detector=DoomLoopDetector(),
    )


class AgentRuntimeCancellationTests(unittest.TestCase):
    """A cancelled run must finish cleanly, not as an error."""

    def setUp(self) -> None:
        self.agent = _StubAgent()
        self.runtime = AgentRuntime(self.agent)
        self.recorder = _EventRecorder()

    def tearDown(self) -> None:
        self.recorder.detach()

    def _cancel_while_deciding(self) -> None:
        """Stub the model so the user cancels while the step is being planned.

        Cancelling before the run begins is not reachable: the runtime clears a
        stale agent-level flag at start-up, otherwise one cancelled run would
        kill every later one.
        """

        def deciding(system: str, user: str) -> str:
            self.agent.cancel_event.set()
            return '{"action_type": "tool", "tool_name": "network_inspect", "arguments": {}}'

        self.runtime._call_llm = deciding

    def test_mid_run_cancel_reports_user_cancelled(self) -> None:
        self._cancel_while_deciding()

        result = self.runtime.run_investigation("inspect the network", session_id="s1")

        self.assertEqual(result.finish_reason, FinishReason.USER_CANCELLED.value)
        self.assertFalse(result.success)
        self.assertIn("cancelled", result.response.lower())
        self.assertNotIn(
            "unexpected error",
            result.response.lower(),
            "cancellation must not surface as an exception",
        )

    def test_cancelled_run_publishes_cancelled_and_no_response_event(self) -> None:
        self._cancel_while_deciding()

        self.runtime.run_investigation("inspect the network", session_id="s1")

        types = self.recorder.types()
        self.assertIn("agent_cancelled", types)
        self.assertNotIn(
            "response",
            types,
            "a cancelled run must not also publish a final response",
        )

    def test_cancelled_run_does_not_execute_the_planned_tool(self) -> None:
        self._cancel_while_deciding()

        self.runtime.run_investigation("inspect the network", session_id="s1")

        self.assertEqual(self.agent.executed, [])

    def test_cancel_run_stops_an_in_flight_investigation(self) -> None:
        inv_id = "inv_cancel_me"

        def deciding(system: str, user: str) -> str:
            self.runtime.cancel_run(inv_id)
            return '{"action_type": "tool", "tool_name": "network_inspect", "arguments": {}}'

        self.runtime._call_llm = deciding

        result = self.runtime.run_investigation(
            "inspect the network", session_id="s1", investigation_id=inv_id
        )

        self.assertEqual(result.finish_reason, FinishReason.USER_CANCELLED.value)
        self.assertFalse(
            self.agent.cancel_event.is_set(),
            "per-run cancellation must not set the agent-wide flag",
        )

    def test_stale_agent_cancel_flag_does_not_kill_a_fresh_run(self) -> None:
        self.agent.cancel_event.set()
        self.runtime._call_llm = lambda system, user: (
            '{"action_type": "final_answer", "response": "clean"}'
        )

        result = self.runtime.run_investigation("check the network", session_id="s1")

        self.assertEqual(result.finish_reason, FinishReason.COMPLETE.value)

    def test_cancel_run_targets_a_single_investigation(self) -> None:
        state_a = _make_state(self.runtime)
        state_b = _make_state(self.runtime)
        state_b.investigation_id = "inv_other"
        self.runtime._active_runs = {"inv_test": state_a, "inv_other": state_b}

        self.assertTrue(self.runtime.cancel_run("inv_test"))
        self.assertTrue(state_a.cancel_event.is_set())
        self.assertFalse(state_b.cancel_event.is_set())
        self.assertFalse(self.runtime.cancel_run("inv_missing"))

    def test_run_state_is_not_shared_between_runs(self) -> None:
        a = _make_state(self.runtime)
        b = _make_state(self.runtime)
        a.stop_conditions.record_step(tokens_used=10)

        self.assertEqual(a.stop_conditions.steps_executed, 1)
        self.assertEqual(
            b.stop_conditions.steps_executed,
            0,
            "each investigation needs its own step budget",
        )


class ContextRenderingTests(unittest.TestCase):
    """The prompt is rendered from the pruned record, so pruning is real."""

    def setUp(self) -> None:
        self.runtime = AgentRuntime(_StubAgent())
        self.state = _make_state(self.runtime)

    def test_render_includes_tool_and_subagent_steps(self) -> None:
        self.state.steps_record = [
            {"step": 1, "tool": "network_inspect", "success": True, "output": "port 443 open"},
            {
                "step": 2,
                "type": "subagent",
                "profile": "Threat Analysis Specialist",
                "verdict": "confirmed",
                "confidence": "high",
                "output": "matches known campaign",
            },
        ]

        rendered = self.runtime._render_context(self.state)

        self.assertIn("check the network", rendered)
        self.assertIn("network_inspect", rendered)
        self.assertIn("port 443 open", rendered)
        self.assertIn("Threat Analysis Specialist", rendered)
        self.assertIn("matches known campaign", rendered)

    def test_render_includes_prior_session_turns_without_tool_noise(self) -> None:
        self.state.conversation_history = [
            {"role": "user", "content": "Check the login service"},
            {"role": "assistant", "content": "I found no failed logins."},
        ]

        rendered = self.runtime._render_context(self.state)

        self.assertIn("Prior conversation", rendered)
        self.assertIn("Check the login service", rendered)
        self.assertIn("I found no failed logins.", rendered)

    def test_render_caps_each_step_output(self) -> None:
        self.state.steps_record = [
            {"step": 1, "tool": "web_search", "success": True, "output": "x" * 50_000}
        ]

        rendered = self.runtime._render_context(self.state)

        self.assertLess(len(rendered), STEP_RENDER_CHARS + 500)
        self.assertIn("[truncated]", rendered)

    def test_pruning_shrinks_what_the_model_sees(self) -> None:
        # Well past DEFAULT_TOOL_OUTPUT_TOKEN_BUDGET (25k tokens ~ 100k chars).
        self.state.steps_record = [
            {"step": i, "tool": "web_search", "success": True, "output": "y" * 40_000}
            for i in range(1, 8)
        ]
        before = self.runtime._render_context(self.state)

        result = self.runtime.compactor.prune_tool_steps(self.state.steps_record)
        self.state.steps_record = result.steps
        after = self.runtime._render_context(self.state)

        self.assertGreater(result.pruned_count, 0)
        self.assertLess(len(after), len(before))

    def test_render_keeps_only_recent_notices(self) -> None:
        self.state.notices = [f"notice {i}" for i in range(10)]

        rendered = self.runtime._render_context(self.state)

        self.assertNotIn("notice 0", rendered)
        self.assertIn("notice 9", rendered)


class UnknownToolFeedbackTests(unittest.TestCase):
    """An unregistered tool name is corrected, not silently dropped."""

    def setUp(self) -> None:
        self.runtime = AgentRuntime(_StubAgent(tool_names=["network_inspect", "web_search"]))
        self.state = _make_state(self.runtime)

    def test_rejection_adds_a_corrective_notice(self) -> None:
        escalation = self.runtime._reject_unknown_tool(
            self.state, "netwrk_inspect", ["network_inspect", "web_search"]
        )

        self.assertIsNone(escalation)
        self.assertEqual(len(self.state.notices), 1)
        self.assertIn("netwrk_inspect", self.state.notices[0])
        self.assertIn("network_inspect", self.state.notices[0], "should suggest the near match")

    def test_repeated_rejection_forces_a_conclusion(self) -> None:
        names = ["network_inspect"]
        self.assertIsNone(self.runtime._reject_unknown_tool(self.state, "nope", names))
        self.assertIsNone(self.runtime._reject_unknown_tool(self.state, "nope", names))
        escalation = self.runtime._reject_unknown_tool(self.state, "nope", names)

        self.assertIsNotNone(escalation)
        self.assertEqual(escalation["action_type"], "final_answer")
        self.assertEqual(self.state.rejected_tools["nope"], 3)

    def test_unknown_tool_never_reaches_execute_tool(self) -> None:
        agent = _StubAgent(tool_names=["network_inspect"])
        runtime = AgentRuntime(agent)
        runtime.max_steps = 4
        runtime._call_llm = lambda system, user: (
            '{"action_type": "tool", "tool_name": "ghost_tool", "arguments": {}}'
        )
        runtime._synthesize_final_report = lambda **kwargs: "report"

        result = runtime.run_investigation("do something", session_id="s2")

        self.assertEqual(agent.executed, [], "a tool that does not exist must not be invoked")
        self.assertLessEqual(result.steps_executed, runtime.max_steps)


class RecoveryTests(unittest.TestCase):
    """A queued recovery plan is executed, not discarded."""

    def setUp(self) -> None:
        self.runtime = AgentRuntime(_StubAgent())
        self.state = _make_state(self.runtime)

    def test_pending_recovery_is_consumed_first(self) -> None:
        recovery = {"action_type": "tool", "tool_name": "web_search", "is_recovery": True}
        self.state.pending_recovery = recovery
        self.runtime._call_llm = lambda system, user: self.fail(
            "the model must not be consulted while a recovery plan is queued"
        )

        decision = self.runtime._decide_next_step(
            state=self.state,
            system_prompt="",
            conversation_context="",
            step_index=2,
        )

        self.assertIs(decision, recovery)
        self.assertIsNone(self.state.pending_recovery, "recovery must be consumed exactly once")

    def test_recovery_is_attempted_once_per_tool(self) -> None:
        self.state.steps_record = [
            {"step": 1, "tool": "network_inspect", "success": False, "output": "boom"}
        ]
        calls: List[str] = []

        def fake_recovery(**kwargs: Any) -> Optional[Dict[str, Any]]:
            calls.append(kwargs["failed_tool"])
            return None

        self.runtime._llm_recovery_decision = fake_recovery
        self.runtime._llm_decide_action = lambda **kwargs: {"action_type": "final_answer"}

        for _ in range(3):
            self.runtime._decide_next_step(
                state=self.state, system_prompt="", conversation_context="", step_index=2
            )

        self.assertEqual(calls, ["network_inspect"], "one recovery attempt per failing tool")

    def test_recovery_rejects_repeating_the_failed_tool(self) -> None:
        self.runtime._call_llm = lambda system, user: (
            '{"action_type": "tool", "tool_name": "network_inspect", "is_recovery": true}'
        )

        decision = self.runtime._llm_recovery_decision(
            state=self.state,
            system_prompt="",
            conversation_context="",
            failed_tool="network_inspect",
            failed_args={},
            failed_output="boom",
        )

        self.assertIsNone(decision)


class FindingAttributionTests(unittest.TestCase):
    """Findings come from the tool, not from keywords in its output."""

    def test_output_mentioning_threat_is_not_a_finding(self) -> None:
        result = AgentRuntime._finding_from_result(
            "web_search",
            {"success": True, "output": "Top threat intelligence blogs of 2026"},
            "Top threat intelligence blogs of 2026",
        )
        self.assertIsNone(result)

    def test_reported_finding_is_kept(self) -> None:
        result = AgentRuntime._finding_from_result(
            "windows_defender_scan",
            {
                "success": True,
                "output": "scan done",
                "finding": {"title": "Trojan detected", "severity": "high", "evidence": "x.exe"},
            },
            "scan done",
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["title"], "Trojan detected")
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["tool"], "windows_defender_scan")

    def test_findings_list_is_accepted(self) -> None:
        result = AgentRuntime._finding_from_result(
            "static_analysis",
            {"success": True, "findings": [{"title": "Hardcoded secret", "severity": "critical"}]},
            "raw",
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "critical")

    def test_empty_findings_list_is_not_a_finding(self) -> None:
        self.assertIsNone(
            AgentRuntime._finding_from_result("static_analysis", {"findings": []}, "raw")
        )


class ToolArgumentTests(unittest.TestCase):
    """No placeholder targets: arguments come from the request or are omitted."""

    def setUp(self) -> None:
        self.runtime = AgentRuntime(_StubAgent())

    def test_open_url_without_a_url_yields_no_url_argument(self) -> None:
        args = self.runtime._build_tool_args("open_url", "go look this up for me")
        self.assertNotIn("url", args)

    def test_open_url_uses_the_url_in_the_request(self) -> None:
        args = self.runtime._build_tool_args("open_url", "check https://nvd.nist.gov/vuln please")
        self.assertEqual(args["url"], "https://nvd.nist.gov/vuln")

    def test_static_analysis_without_a_path_yields_no_code(self) -> None:
        args = self.runtime._build_tool_args("static_analysis", "review my code")
        self.assertNotIn("code", args)
        self.assertNotIn("filepath", args)

    def test_static_analysis_sends_source_text_not_a_path(self) -> None:
        # The registered tool is StaticCodeAnalyzer.analyze_python_code(code).
        # Passing filepath raised TypeError inside the tool, so every SAST step
        # failed before the analyzer ran.
        args = self.runtime._build_tool_args("static_analysis", "scan cyber_agent.py for issues")
        self.assertNotIn("filepath", args)
        self.assertIn("import json", args["code"])

    def test_static_analysis_with_an_unreadable_path_yields_no_code(self) -> None:
        args = self.runtime._build_tool_args("static_analysis", "scan no_such_file.py please")
        self.assertNotIn("code", args)

    def test_url_from_context_is_empty_when_none_present(self) -> None:
        self.assertEqual(self.runtime._extract_url_from_context("no links here"), "")

    def test_heuristic_skips_open_url_without_a_target(self) -> None:
        state = _make_state(self.runtime, user_input="browse for recent CVEs")
        state.steps_record = [{"step": 1, "tool": "web_search", "success": True, "output": "none"}]

        decision = self.runtime._heuristic_decide_action(
            state=state, conversation_context="nothing linkable", step_index=2
        )

        self.assertNotEqual(decision.get("tool_name"), "open_url")


class ScreenshotPathTests(unittest.TestCase):
    """Screenshots resolve from the project root, not a machine-specific path."""

    def test_non_browser_tool_captures_nothing(self) -> None:
        runtime = AgentRuntime(_StubAgent())
        self.assertIsNone(runtime._capture_browser_screenshot("network_inspect", True, 1))

    def test_failed_browser_tool_captures_nothing(self) -> None:
        runtime = AgentRuntime(_StubAgent())
        self.assertIsNone(runtime._capture_browser_screenshot("web_search", False, 1))


class LoopCompletionTests(unittest.TestCase):
    """End-to-end control flow with a stubbed model."""

    def test_final_answer_completes_and_publishes_response(self) -> None:
        agent = _StubAgent()
        runtime = AgentRuntime(agent)
        runtime._call_llm = lambda system, user: (
            '{"action_type": "final_answer", "response": "No malicious activity observed."}'
        )
        recorder = _EventRecorder()
        try:
            result = runtime.run_investigation("check the network", session_id="s3")
        finally:
            recorder.detach()

        self.assertTrue(result.success)
        self.assertEqual(result.finish_reason, FinishReason.COMPLETE.value)
        self.assertEqual(result.response, "No malicious activity observed.")
        types = recorder.types()
        self.assertIn("agent_completed", types)
        self.assertEqual(types.count("response"), 1, "exactly one response event per run")

    def test_empty_final_answer_is_synthesized_not_published_blank(self) -> None:
        agent = _StubAgent()
        runtime = AgentRuntime(agent)
        runtime._call_llm = lambda system, user: '{"action_type": "final_answer", "response": ""}'
        runtime._synthesize_final_report = lambda **kwargs: "Synthesized report."

        result = runtime.run_investigation("check the network", session_id="s4")

        self.assertEqual(result.response, "Synthesized report.")

    def test_tool_step_runs_then_concludes(self) -> None:
        agent = _StubAgent(
            tool_names=["network_inspect"],
            tool_results={"network_inspect": {"success": True, "output": "no listeners" * 30}},
        )
        runtime = AgentRuntime(agent)
        responses = iter([
            '{"action_type": "tool", "tool_name": "network_inspect", "arguments": {}}',
            '{"action_type": "final_answer", "response": "Network is clean."}',
        ])
        runtime._call_llm = lambda system, user: next(responses)

        result = runtime.run_investigation("inspect the network", session_id="s5")

        self.assertEqual(agent.executed, ["network_inspect"])
        self.assertEqual(result.response, "Network is clean.")
        self.assertEqual(result.steps_executed, 2)

    def test_runtime_deregisters_the_run_when_finished(self) -> None:
        agent = _StubAgent()
        runtime = AgentRuntime(agent)
        runtime._call_llm = lambda system, user: '{"action_type": "final_answer", "response": "ok"}'

        runtime.run_investigation("check the network", session_id="s6")

        self.assertEqual(runtime.active_run_ids(), [])


if __name__ == "__main__":
    unittest.main()
