"""
tests/test_path_extraction.py — Tools must act on the file the user named,
never on a stand-in.

Three call sites used to pass a fixed sample path ("ideas/code 1") when the
request named no file. That is worse than doing nothing: the tool succeeds, the
output looks like evidence, and the report describes a file the investigation
never mentioned. These tests pin the replacement behaviour — extract the real
path, and when there is none, say so instead of substituting one.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict, List

from cyber_os.subagents.contracts import (
    SubagentContextRef,
    SubagentProfile,
    SubagentTaskRequest,
)
from cyber_os.subagents.manager import (
    _BINARY_FILE_PATTERN,
    _SOURCE_FILE_PATTERN,
    _first_path,
)


def _task(objective: str, context: List[str] | None = None) -> SubagentTaskRequest:
    return SubagentTaskRequest(
        subagent_id="sub-1",
        parent_investigation_id="inv-1",
        profile=SubagentProfile.MALWARE_ANALYSIS,
        objective=objective,
        context_refs=[SubagentContextRef(label=f"ctx{i}", content=c) for i, c in enumerate(context or [])],
    )


class FirstPathTests(unittest.TestCase):
    def test_finds_a_binary_named_in_the_objective(self) -> None:
        task = _task("Assess the packer used by samples/dropper.exe")
        self.assertEqual(_first_path(task, _BINARY_FILE_PATTERN), "samples/dropper.exe")

    def test_finds_a_source_file_named_in_the_objective(self) -> None:
        task = _task("Review src/auth/login.py for injection risk")
        self.assertEqual(_first_path(task, _SOURCE_FILE_PATTERN), "src/auth/login.py")

    def test_returns_empty_when_no_file_is_named(self) -> None:
        task = _task("Analyze the malicious code we discussed")
        self.assertEqual(_first_path(task, _BINARY_FILE_PATTERN, _SOURCE_FILE_PATTERN), "")

    def test_objective_wins_over_parent_context(self) -> None:
        task = _task("Check samples/target.exe", context=["earlier we looked at other/decoy.exe"])
        self.assertEqual(_first_path(task, _BINARY_FILE_PATTERN), "samples/target.exe")

    def test_falls_back_to_parent_context(self) -> None:
        task = _task("Check the dropped binary", context=["the dropped file was C:/tmp/stage2.dll"])
        self.assertEqual(_first_path(task, _BINARY_FILE_PATTERN), "C:/tmp/stage2.dll")

    def test_a_url_is_not_mistaken_for_a_local_file(self) -> None:
        task = _task("Fetch https://evil.example/payload.exe and assess it")
        self.assertNotIn("https", _first_path(task, _BINARY_FILE_PATTERN))

    def test_pattern_order_selects_the_preferred_kind(self) -> None:
        # A malware specialist wants the executable, not the README beside it.
        task = _task("Compare notes.md against samples/payload.exe")
        self.assertEqual(
            _first_path(task, _BINARY_FILE_PATTERN, _SOURCE_FILE_PATTERN),
            "samples/payload.exe",
        )


class _RecordingAgent:
    """Minimal stand-in that records the tool calls a specialist makes."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def execute_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append({"tool": name, "args": args})
        return {"success": True, "output": "entropy 7.9"}


class MalwareSpecialistToolSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        from cyber_os.subagents.manager import SubagentManager
        from cyber_os.subagents.profiles import DEFENSIVE_SPECIALIST_PROFILES

        self.agent = _RecordingAgent()
        self.manager = SubagentManager(self.agent)
        self.definition = DEFENSIVE_SPECIALIST_PROFILES[SubagentProfile.MALWARE_ANALYSIS]

    def test_entropy_check_runs_against_the_named_file(self) -> None:
        task = _task("Entropy-check samples/dropper.exe")
        result = self.manager._execute_subagent_tools(task, self.definition)

        self.assertEqual(len(self.agent.calls), 1)
        self.assertEqual(self.agent.calls[0]["tool"], "entropy_check")
        self.assertEqual(self.agent.calls[0]["args"]["filepath"], "samples/dropper.exe")
        self.assertIn("file:samples/dropper.exe", result["evidence_refs"])

    def test_no_file_named_means_no_tool_call(self) -> None:
        task = _task("Look into the suspicious code behaviour")
        result = self.manager._execute_subagent_tools(task, self.definition)

        self.assertEqual(self.agent.calls, [], "must not fall back to a sample file")
        self.assertEqual(result["tool_calls_count"], 0)
        self.assertEqual(result["evidence_refs"], [])


class AgentFileTargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from cyber_agent import CyberAgent

        # staticmethod() keeps this a plain function: a bare assignment would
        # rebind it as a method of the test case and inject `self` as the input.
        cls.extract = staticmethod(CyberAgent._extract_file_target)

    def test_extracts_a_relative_source_path(self) -> None:
        self.assertEqual(self.extract("please scan code in src/app/main.py"), "src/app/main.py")

    def test_extracts_a_windows_path(self) -> None:
        self.assertEqual(
            self.extract(r"entropy check on C:\samples\stage2.dll"),
            r"C:\samples\stage2.dll",
        )

    def test_extension_match_is_case_insensitive(self) -> None:
        self.assertEqual(self.extract("inspect Payload.EXE now"), "Payload.EXE")

    def test_quoted_path_without_an_extension(self) -> None:
        self.assertEqual(self.extract('scan code in "build/output/bundle"'), "build/output/bundle")

    def test_returns_empty_when_nothing_is_named(self) -> None:
        self.assertEqual(self.extract("scan the code for vulnerabilities"), "")


if __name__ == "__main__":
    unittest.main()
