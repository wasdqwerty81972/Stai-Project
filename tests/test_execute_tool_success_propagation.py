"""
tests/test_execute_tool_success_propagation.py -- regression cover for the
executor's python_func result contract.

Collapsing 59 per-CLI wrapper tools into one ``shell_exec`` moved every command
off ``execute_tool``'s legacy command path (which derived success from the
process return code) and onto its *python_func* branch. That branch reported
``success: True`` for any call that merely returned without raising, so a
nonzero exit, an unknown preset, a missing parameter, or an absent binary all
surfaced to callers as a clean run -- the tool's own ``{"success": False}`` was
buried inside the JSON-serialised ``output`` string where nothing looked for it.

tests/test_tool_absence.py already pins the *inner* layer (ShellExecTool._execute
returns the tool_absent shape). These tests cover the layer above it, where that
verdict was being discarded.

The contract pinned here: a tool that reports its own outcome has that outcome
honoured, and a tool that reports none keeps the original optimistic default.
"""

from __future__ import annotations

import json
import unittest

from cyber_agent import CyberAgent
from cyber_tools import RiskLevel, ToolDefinition


class _ExecuteToolHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = CyberAgent(workspace_path=".")
        # The approval gate has its own coverage; what is under test here is the
        # shape of the result *after* a tool has run.
        self.agent._wait_for_approval = lambda *args, **kwargs: True

    def _register(self, name: str, result: object) -> str:
        self.agent.registry.tools[name] = ToolDefinition(
            name=name,
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=lambda **kwargs: result,
        )
        self.addCleanup(self.agent.registry.tools.pop, name, None)
        return name


class PythonFuncSuccessPropagationTests(_ExecuteToolHarness):
    def test_self_reported_failure_is_not_overwritten_with_success(self) -> None:
        """The shell_exec tool_absent shape: a scanner that was never installed
        must not read as a scan that found nothing."""
        name = self._register(
            "_test_absent_tool",
            {
                "success": False,
                "status": "tool_absent",
                "output": "",
                "error": "MpCmdRun.exe: not found",
            },
        )
        res = self.agent.execute_tool(name, {})
        self.assertFalse(res["success"])
        self.assertIn("not found", res["error"])

    def test_self_reported_failure_surfaces_the_tools_own_error(self) -> None:
        name = self._register(
            "_test_failing_tool",
            {"success": False, "output": "", "error": "Unknown preset 'nope'."},
        )
        res = self.agent.execute_tool(name, {})
        self.assertFalse(res["success"])
        self.assertEqual(res["error"], "Unknown preset 'nope'.")

    def test_self_reported_success_is_preserved(self) -> None:
        name = self._register(
            "_test_ok_tool", {"success": True, "output": "hi", "error": ""}
        )
        res = self.agent.execute_tool(name, {})
        self.assertTrue(res["success"])
        self.assertEqual(res["error"], "")

    def test_tool_without_a_success_key_still_defaults_to_success(self) -> None:
        """Most python_func tools return a plain payload and signal failure by
        raising. Their behaviour is deliberately unchanged."""
        name = self._register("_test_plain_tool", {"findings": [1, 2, 3]})
        res = self.agent.execute_tool(name, {})
        self.assertTrue(res["success"])
        self.assertEqual(res["error"], "")

    def test_non_dict_result_still_defaults_to_success(self) -> None:
        name = self._register("_test_str_tool", "plain text result")
        res = self.agent.execute_tool(name, {})
        self.assertTrue(res["success"])
        self.assertEqual(res["output"], "plain text result")

    def test_full_payload_is_still_serialised_into_output(self) -> None:
        """Honouring the inner verdict must not cost callers the payload: the
        whole dict is still available as JSON in ``output``."""
        payload = {"success": False, "error": "boom", "detail": {"k": "v"}}
        name = self._register("_test_payload_tool", payload)
        res = self.agent.execute_tool(name, {})
        self.assertEqual(json.loads(res["output"]), payload)
        self.assertEqual(res["tool"], name)
        self.assertIn("environment_used", res)


if __name__ == "__main__":
    unittest.main()
