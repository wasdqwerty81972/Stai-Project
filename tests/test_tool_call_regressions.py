"""
tests/test_tool_call_regressions.py — regressions in the model-driven tool path.

Each test here corresponds to a defect that let a broken tool call reach the
user: a model reply that could not be parsed, a provider failure rendered as an
answer, a finding that never surfaced, a heuristic step naming a tool that does
not exist, and an approval wait that outlived a cancelled run.
"""

from __future__ import annotations

import os
import sys
import threading
import unittest
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_os.agent_runtime import AgentRuntime  # noqa: E402
from cyber_os.llm_json import extract_json_object, is_ai_error_marker  # noqa: E402
from cyber_os.stop_conditions import FinishReason  # noqa: E402
from ui.event_bus import AgentEvent, event_bus  # noqa: E402


class _StubTool:
    def __init__(self, name: str) -> None:
        self.name = name

    def to_manifest(self) -> Dict[str, Any]:
        return {"name": self.name, "description": f"stub {self.name}"}


class _StubRegistry:
    def __init__(self, tool_names: List[str]) -> None:
        self.tools = {name: _StubTool(name) for name in tool_names}


class _StubAgent:
    def __init__(
        self,
        tool_names: Optional[List[str]] = None,
        tool_results: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self.registry = _StubRegistry(tool_names or ["network_inspect"])
        self.workspace_path = "."
        self.cancel_event = threading.Event()
        self.tool_results = tool_results or {}
        self.executed: List[str] = []

    def execute_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        self.executed.append(name)
        return self.tool_results.get(name, {"success": True, "output": "ok " * 60})


class _EventRecorder:
    def __init__(self) -> None:
        self.events: List[AgentEvent] = []
        event_bus.subscribe_all(self._on_event)

    def _on_event(self, event: AgentEvent) -> None:
        self.events.append(event)

    def detach(self) -> None:
        with event_bus._lock:
            event_bus._global_listeners = [
                cb for cb in event_bus._global_listeners if cb != self._on_event
            ]

    def types(self) -> List[str]:
        return [e.type for e in self.events]


class JsonExtractionTests(unittest.TestCase):
    """A prose-wrapped or fenced reply must still yield its JSON object.

    The previous greedy ``\\{.*\\}`` span broke whenever the surrounding text
    contained braces or the model emitted more than one object, and the caller
    then silently fell back to a non-model decision.
    """

    def test_plain_object(self) -> None:
        self.assertEqual(extract_json_object('{"action_type": "final_answer"}'), {"action_type": "final_answer"})

    def test_object_wrapped_in_prose(self) -> None:
        reply = 'Here is my decision:\n{"action_type": "final_answer", "response": "ok"}\nHope that helps.'
        self.assertEqual(extract_json_object(reply)["action_type"], "final_answer")

    def test_fenced_block(self) -> None:
        reply = '```json\n{"action_type": "tool", "tool_name": "network_inspect"}\n```'
        self.assertEqual(extract_json_object(reply)["tool_name"], "network_inspect")

    def test_braces_in_surrounding_prose_do_not_break_the_parse(self) -> None:
        # The old greedy span ran from this first "{" to the final "}", which
        # is not valid JSON, so the whole decision was discarded.
        reply = 'Considering {options} and {trade-offs}, I choose: {"action_type": "final_answer", "response": "clean"}'
        parsed = extract_json_object(reply)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["response"], "clean")

    def test_brace_inside_a_string_does_not_end_the_object(self) -> None:
        parsed = extract_json_object('{"response": "a } brace", "action_type": "final_answer"}')
        self.assertEqual(parsed["response"], "a } brace")

    def test_no_json_returns_none(self) -> None:
        self.assertIsNone(extract_json_object("I cannot decide."))
        self.assertIsNone(extract_json_object(""))
        self.assertIsNone(extract_json_object(None))

    def test_error_marker_is_not_mistaken_for_output(self) -> None:
        # Matches CyberAgent's marker format, and the prefix rule the subagent
        # verdict path already relied on.
        self.assertTrue(is_ai_error_marker("[AI ERROR] investigator failed: 401"))
        self.assertFalse(is_ai_error_marker("Investigator failed: 401"))
        self.assertFalse(is_ai_error_marker(""))
        self.assertFalse(is_ai_error_marker(None))

    def test_every_backend_failure_marker_is_recognised(self) -> None:
        # AgentRuntime._call_llm falls back to LLMClient when the orchestrator
        # exposes no _call_role, and that client uses different markers.
        self.assertTrue(is_ai_error_marker("[LLM error] 401 unauthorized"))
        self.assertTrue(is_ai_error_marker("[LLM unavailable] could not initialize AiApi."))

    def test_a_provider_failure_is_not_published_as_the_report(self) -> None:
        # Whichever backend answered, an infrastructure failure must not be
        # presented to the user as the investigation's conclusion.
        runtime = AgentRuntime(_StubAgent())
        for marker in (
            "[AI ERROR] investigator failed: 401",
            "[LLM error] 401 unauthorized",
            "[LLM unavailable] key_manager.py could not initialize AiApi.",
        ):
            with self.subTest(marker=marker):
                runtime._call_llm = lambda system, user, m=marker: m
                report = runtime._synthesize_final_report(
                    user_input="check the network",
                    system_prompt="",
                    conversation_context="[Tool 'network_inspect' Result]:\nno listeners",
                    findings=[],
                )
                self.assertNotIn("[LLM", report)
                self.assertNotIn("[AI ERROR]", report)
                self.assertIn("Investigation Report (offline)", report)


class DecisionParsingTests(unittest.TestCase):
    """A fenced or prose-wrapped decision still reaches the tool."""

    def setUp(self) -> None:
        self.agent = _StubAgent(tool_names=["network_inspect"])
        self.runtime = AgentRuntime(self.agent)

    def _state(self, user_input: str = "inspect the network"):
        from cyber_os.doom_loop_detector import DoomLoopDetector
        from cyber_os.stop_conditions import StopConditions

        from cyber_os.agent_runtime import _RunState

        return _RunState(
            investigation_id="inv_parse",
            session_id="sess_parse",
            user_input=user_input,
            cancel_event=threading.Event(),
            stop_conditions=StopConditions(max_steps=5, max_elapsed_seconds=30.0),
            doom_loop_detector=DoomLoopDetector(),
        )

    def test_fenced_decision_is_honoured(self) -> None:
        self.runtime._call_llm = lambda system, user: (
            '```json\n{"action_type": "tool", "tool_name": "network_inspect", "arguments": {}}\n```'
        )
        decision = self.runtime._llm_decide_action(
            state=self._state(),
            system_prompt="",
            conversation_context="",
            step_index=1,
        )
        self.assertEqual(decision["tool_name"], "network_inspect")

    def test_provider_failure_falls_back_to_heuristics(self) -> None:
        # The error marker must not be parsed as a decision. "inspect the
        # network" is a keyword the heuristic handles, so a tool step here is
        # the fallback working; what matters is that the name is one the
        # executor would actually accept.
        self.runtime._call_llm = lambda system, user: "[AI ERROR] investigator failed: 401 unauthorized"
        decision = self.runtime._llm_decide_action(
            state=self._state(),
            system_prompt="",
            conversation_context="",
            step_index=1,
        )
        if decision.get("action_type") == "tool":
            self.assertIn(decision["tool_name"], self.agent.registry.tools)
        else:
            self.assertEqual(decision["action_type"], "final_answer")

    def test_error_marker_is_not_read_as_a_json_decision(self) -> None:
        self.runtime._call_llm = lambda system, user: (
            '[AI ERROR] investigator failed: bad request {"action_type": "tool", "tool_name": "made_up"}'
        )
        decision = self.runtime._llm_decide_action(
            state=self._state(user_input="unrelated request"),
            system_prompt="",
            conversation_context="",
            step_index=1,
        )
        self.assertNotEqual(decision.get("tool_name"), "made_up")


class FinalReportTests(unittest.TestCase):
    """A provider failure must not be handed to the user as the report."""

    def setUp(self) -> None:
        self.runtime = AgentRuntime(_StubAgent())

    def test_ai_error_is_not_published_as_the_report(self) -> None:
        self.runtime._call_llm = lambda system, user: "[AI ERROR] investigator failed: 401 unauthorized"
        report = self.runtime._synthesize_final_report(
            user_input="check the network",
            system_prompt="",
            conversation_context="[Tool 'network_inspect' Result]:\nno listeners",
            findings=[],
        )
        self.assertNotIn("[AI ERROR]", report)
        self.assertIn("Investigation Report (offline)", report)

    def test_a_real_report_is_used(self) -> None:
        self.runtime._call_llm = lambda system, user: "## Executive Summary\nAll clear."
        report = self.runtime._synthesize_final_report(
            user_input="check the network",
            system_prompt="",
            conversation_context="",
            findings=[],
        )
        self.assertEqual(report, "## Executive Summary\nAll clear.")


class PresetToolTests(unittest.TestCase):
    """The heuristic path must propose tools that exist.

    ``windows_defender_scan`` is a command preset invoked through
    ``shell_exec(preset=...)``, not a registry entry, so the old heuristic step
    was rejected by the executor and the scan never ran.
    """

    def setUp(self) -> None:
        self.agent = _StubAgent(tool_names=["shell_exec", "network_inspect"])
        self.runtime = AgentRuntime(self.agent)

    def _state(self, user_input: str):
        from cyber_os.agent_runtime import _RunState
        from cyber_os.doom_loop_detector import DoomLoopDetector
        from cyber_os.stop_conditions import StopConditions

        return _RunState(
            investigation_id="inv_preset",
            session_id="sess_preset",
            user_input=user_input,
            cancel_event=threading.Event(),
            stop_conditions=StopConditions(max_steps=5, max_elapsed_seconds=30.0),
            doom_loop_detector=DoomLoopDetector(),
        )

    def test_malware_request_uses_a_registered_tool(self) -> None:
        decision = self.runtime._heuristic_decide_action(
            state=self._state("check this malware download in samples"),
            conversation_context="",
            step_index=1,
        )
        self.assertIn(
            decision.get("tool_name"),
            self.agent.registry.tools,
            "heuristic proposed a tool the executor would reject",
        )

    def test_defender_request_uses_the_shell_exec_preset(self) -> None:
        if "windows_defender_scan" not in self.runtime._preset_names():
            self.skipTest("preset catalogue unavailable")
        decision = self.runtime._heuristic_decide_action(
            state=self._state("run defender on samples"),
            conversation_context="",
            step_index=1,
        )
        self.assertEqual(decision["tool_name"], "shell_exec")
        self.assertEqual(decision["arguments"]["preset"], "windows_defender_scan")

    def test_shell_exec_args_carry_preset_and_params(self) -> None:
        args = self.runtime._build_tool_args("shell_exec", "run a defender scan on C:/samples/payload.exe")
        self.assertEqual(args.get("preset"), "windows_defender_scan")
        self.assertEqual(args["params"]["target"], "C:/samples/payload.exe")

    def test_shell_exec_omits_params_when_no_real_target_is_named(self) -> None:
        # An unfilled {target} makes shell_exec fail closed to DESTRUCTIVE, so
        # a targetless preset call is left to the tool to report.
        args = self.runtime._build_tool_args("shell_exec", "run a defender scan on whatever you find")
        self.assertEqual(args.get("preset"), "windows_defender_scan")
        self.assertNotIn("params", args)

    def test_shell_exec_is_left_alone_for_unrelated_requests(self) -> None:
        self.assertEqual(self.runtime._build_tool_args("shell_exec", "list the todos"), {})


class FindingPropagationTests(unittest.TestCase):
    """A tool's reported findings must reach the runtime, not just its log line."""

    def test_findings_from_a_tool_reach_the_run(self) -> None:
        agent = _StubAgent(
            tool_names=["network_inspect"],
            tool_results={
                "network_inspect": {
                    "success": True,
                    "output": "detail " * 40,
                    "findings": [{"title": "Suspicious listener", "severity": "high"}],
                }
            },
        )
        runtime = AgentRuntime(agent)
        responses = iter([
            '{"action_type": "tool", "tool_name": "network_inspect", "arguments": {}}',
            '{"action_type": "final_answer", "response": "Found one listener."}',
        ])
        runtime._call_llm = lambda system, user: next(responses)

        result = runtime.run_investigation("inspect the network", session_id="s_find")

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0]["title"], "Suspicious listener")


class ExecutionContractTests(unittest.TestCase):
    """execute_tool's own result contract, against a real CyberAgent."""

    @classmethod
    def setUpClass(cls) -> None:
        from cyber_agent import CyberAgent

        cls.agent = CyberAgent(workspace_path=".")

    def setUp(self) -> None:
        from cyber_tools import ToolDefinition, RiskLevel

        self.calls: List[str] = []
        marker = self.agent.registry.tools.get("network_inspect")
        self._original = marker
        self.agent.registry.register_tool(
            ToolDefinition(
                name="_probe_finding_tool",
                environments=["cross_platform"],
                command_template="",
                risk_level=RiskLevel.READ_ONLY,
                python_func=lambda **_kw: {
                    "success": True,
                    "output": "scanned",
                    "findings": [{"title": "Backdoor", "severity": "critical"}],
                },
            )
        )

    def test_findings_are_hoisted_to_the_result(self) -> None:
        result = self.agent.execute_tool("_probe_finding_tool", {})
        self.assertTrue(result["success"])
        self.assertEqual(result["findings"][0]["title"], "Backdoor")

    def test_failing_tool_reports_the_failure(self) -> None:
        from cyber_tools import ToolDefinition, RiskLevel

        self.agent.registry.register_tool(
            ToolDefinition(
                name="_probe_fail_tool",
                environments=["cross_platform"],
                command_template="",
                risk_level=RiskLevel.READ_ONLY,
                python_func=lambda **_kw: {"success": False, "error": "binary absent", "output": ""},
            )
        )
        result = self.agent.execute_tool("_probe_fail_tool", {})
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "binary absent")


class ApprovalCancellationTests(unittest.TestCase):
    """A cancelled run must not sit on a pending approval card."""

    @classmethod
    def setUpClass(cls) -> None:
        from cyber_agent import CyberAgent

        cls.agent = CyberAgent(workspace_path=".")

    def test_approval_wait_returns_when_the_run_is_cancelled(self) -> None:
        self.agent.cancel_event.clear()
        timer = threading.Timer(0.3, self.agent.cancel_event.set)
        timer.start()
        try:
            started = threading.Event()
            threading.Timer(0.1, started.set).start()
            started.wait(1.0)
            approved = self.agent._wait_for_approval(
                "shell_exec", "DESTRUCTIVE", {"threat_score": 0}, "tc-1"
            )
        finally:
            timer.cancel()
            self.agent.cancel_event.clear()

        self.assertFalse(approved, "a cancelled run must not be approved")


class LLMClientJsonTests(unittest.TestCase):
    """``LLMClient.chat_json``'s last-resort parse, which fed the agent runtime.

    The fallback used to span from the first ``{`` to the last ``}``. Any brace
    in the surrounding prose produced one undecodable span, so a valid decision
    inside commentary was dropped and the call degraded to ``{"response": ...}``
    — indistinguishable from the model having answered in prose.
    """

    def _client_returning(self, text: str):
        from cyber_os.tool_orchestrator import LLMClient

        client = LLMClient.__new__(LLMClient)
        client.use_mock = True
        client._api = None
        client.chat = lambda system, user, role="investigator": text  # type: ignore[assignment]
        return client

    def test_a_braced_commentary_tail_does_not_swallow_the_decision(self) -> None:
        client = self._client_returning(
            'Here is my reasoning {I considered network_inspect}.\n'
            '{"action_type": "tool", "tool_name": "network_inspect", "arguments": {}}\n'
            "Note: unrelated {braces} at the end."
        )
        parsed = client.chat_json("system", "user")
        self.assertEqual(parsed.get("tool_name"), "network_inspect")
        self.assertNotIn("response", parsed)

    def test_unparseable_text_still_degrades_to_the_raw_response(self) -> None:
        # No JSON anywhere: returning the text is correct, so the error path
        # stays covered rather than silently raising on the new helper.
        client = self._client_returning("I cannot answer that right now.")
        parsed = client.chat_json("system", "user")
        self.assertEqual(parsed, {"response": "I cannot answer that right now."})


if __name__ == "__main__":
    unittest.main()
