"""
tests/test_agent_loop_e2e.py — The loop must produce a usable investigation
against the real tool registry, with and without an AI provider.

The unit tests in test_agent_runtime_loop.py stub the registry. These run the
same loop over the actual 200+ registered tools so a registration or argument
regression shows up as a failed investigation rather than passing tests.
"""

from __future__ import annotations

import json
import threading
import unittest
from typing import Any, Dict, List, Optional

from cyber_os.agent_runtime import AgentRuntime
from cyber_os.stop_conditions import FinishReason
from cyber_tools import AuditLogger, ToolRegistry, register_all_default_tools


class _ScriptedOrchestrator:
    """Replays a fixed list of decisions, then answers. Records prompts."""

    def __init__(self, decisions: List[Dict[str, Any]]) -> None:
        self._decisions = list(decisions)
        self.prompts: List[str] = []

    def _call_role(self, role: str, system: str, user: str) -> str:
        self.prompts.append(user)
        if self._decisions:
            return json.dumps(self._decisions.pop(0))
        return "## Report\n\nThe investigation completed."


class _OfflineOrchestrator:
    """Stands in for a provider that cannot be reached."""

    def __init__(self) -> None:
        self.calls = 0

    def _call_role(self, role: str, system: str, user: str) -> str:
        self.calls += 1
        raise ConnectionError("provider unreachable")


class _RealToolAgent:
    """CyberAgent's surface for the runtime, backed by the real registry."""

    def __init__(self, orchestrator: Any) -> None:
        self.registry = ToolRegistry(AuditLogger())
        register_all_default_tools(self.registry)
        self.orchestrator = orchestrator
        self.workspace_path = "."
        self.cancel_event = threading.Event()
        self.executed: List[str] = []

    def execute_tool(self, name: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self.executed.append(name)
        definition = self.registry.tools.get(name)
        if definition is None:
            return {"success": False, "error": f"unknown tool: {name}"}
        func = getattr(definition, "python_func", None)
        if func is None:
            return {"success": False, "error": f"{name} has no python implementation"}
        try:
            return {"success": True, "output": str(func(**(args or {})))}
        except Exception as exc:  # a tool refusing bad args is a valid outcome
            return {"success": False, "error": f"{type(exc).__name__}: {exc}"}


class _RealRegistryTestCase(unittest.TestCase):
    """Builds the 200+ tool registry once; registration is the slow part."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._registry = ToolRegistry(AuditLogger())
        register_all_default_tools(cls._registry)

    def _agent(self, orchestrator: Any) -> _RealToolAgent:
        agent = _RealToolAgent.__new__(_RealToolAgent)
        agent.registry = self._registry
        agent.orchestrator = orchestrator
        agent.workspace_path = "."
        agent.cancel_event = threading.Event()
        agent.executed = []
        return agent


class LoopWithRealToolsTests(_RealRegistryTestCase):
    def test_investigation_runs_a_real_tool_and_reports(self) -> None:
        orchestrator = _ScriptedOrchestrator(
            [
                {
                    "action_type": "tool",
                    "tool_name": "workspace_list_files",
                    "arguments": {"root": ".", "pattern": "*.py", "max_results": 5},
                    "brief": "listing project files",
                },
                {"action_type": "final_answer", "response": "## Report\n\nListing succeeded."},
            ]
        )
        agent = self._agent(orchestrator)
        runtime = AgentRuntime(agent)

        result = runtime.run_investigation("list the python files in the workspace")

        self.assertIn("workspace_list_files", agent.executed)
        self.assertTrue(result.success)
        self.assertIn("Listing succeeded", result.response)
        self.assertEqual(result.finish_reason, FinishReason.COMPLETE.value)
        self.assertGreaterEqual(result.steps_executed, 1)
        self.assertEqual(runtime.active_run_ids(), [], "run state must be released")

    def test_unknown_tool_is_refused_and_the_run_still_answers(self) -> None:
        orchestrator = _ScriptedOrchestrator(
            [
                {"action_type": "tool", "tool_name": "definitely_not_a_tool", "arguments": {}},
                {"action_type": "final_answer", "response": "## Report\n\nDone."},
            ]
        )
        agent = self._agent(orchestrator)
        runtime = AgentRuntime(agent)

        result = runtime.run_investigation("run the nonexistent tool")

        self.assertNotIn("definitely_not_a_tool", agent.executed)
        self.assertIn("Done", result.response)

    def test_tool_arguments_are_built_for_a_named_file(self) -> None:
        orchestrator = _ScriptedOrchestrator(
            [
                # No arguments supplied: the runtime must derive them.
                {"action_type": "tool", "tool_name": "static_analysis", "arguments": {}},
                {"action_type": "final_answer", "response": "## Report\n\nAnalysed."},
            ]
        )
        agent = self._agent(orchestrator)
        runtime = AgentRuntime(agent)

        runtime.run_investigation("run static analysis on cyber_agent.py")

        self.assertIn("static_analysis", agent.executed)


class OfflineProviderTests(_RealRegistryTestCase):
    def test_offline_run_still_returns_the_collected_evidence(self) -> None:
        orchestrator = _OfflineOrchestrator()
        agent = self._agent(orchestrator)
        runtime = AgentRuntime(agent)
        runtime.max_steps = 2

        result = runtime.run_investigation("inspect the local network connections")

        self.assertTrue(orchestrator.calls, "the runtime should have attempted the provider")
        self.assertTrue(result.response.strip(), "an offline run must still say something")
        self.assertIn("offline", result.response.lower())
        # The point of the offline path: evidence survives the missing model.
        self.assertIn("Objective", result.response)
        self.assertNotEqual(result.finish_reason, FinishReason.USER_CANCELLED.value)

    def test_offline_run_does_not_report_a_cancellation(self) -> None:
        agent = self._agent(_OfflineOrchestrator())
        runtime = AgentRuntime(agent)
        runtime.max_steps = 1

        runtime.run_investigation("check listening ports")

        self.assertEqual(runtime.active_run_ids(), [])


class OfflineReportTests(unittest.TestCase):
    """_offline_report is pure, so it needs no registry."""

    def test_findings_are_listed_with_severity(self) -> None:
        report = AgentRuntime._offline_report(
            "check for secrets",
            "[Tool 'secret_scan' Result (Success=True)]:\nfound an AWS key",
            [{"title": "Hardcoded AWS key", "severity": "high", "evidence": "AKIA...", "tool": "secret_scan"}],
        )
        self.assertIn("HIGH", report)
        self.assertIn("Hardcoded AWS key", report)
        self.assertIn("AKIA", report)
        self.assertIn("check for secrets", report)

    def test_no_findings_is_stated_explicitly(self) -> None:
        report = AgentRuntime._offline_report("check for secrets", "[Tool 'secret_scan' Result]: clean", [])
        self.assertIn("none reported", report)

    def test_tool_evidence_is_carried_into_the_report(self) -> None:
        report = AgentRuntime._offline_report("x", "PORT 4444 LISTENING", [])
        self.assertIn("PORT 4444 LISTENING", report)

    def test_empty_context_does_not_produce_a_blank_report(self) -> None:
        report = AgentRuntime._offline_report("x", "", [])
        self.assertIn("no tool output recorded", report)


if __name__ == "__main__":
    unittest.main()
