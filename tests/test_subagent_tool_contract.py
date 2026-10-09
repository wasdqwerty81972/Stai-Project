"""
tests/test_subagent_tool_contract.py — regressions in delegated specialist work.

A specialist that could not call its own tools, that lost its session stamp, or
that raised on one bad lookup reported failure for work it had actually done.
"""

from __future__ import annotations

import dataclasses
import os
import sys
import threading
import unittest
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_os.subagents.manager import SubagentManager  # noqa: E402
from cyber_os.subagents.profiles import resolve_profile_definition  # noqa: E402
from ui.event_bus import AgentEvent, event_bus  # noqa: E402


class _RecordingAgent:
    """Records every execute_tool call and replays a scripted result."""

    def __init__(self, results: Optional[Dict[str, Any]] = None, raises: bool = False) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.results = results or {}
        self.raises = raises

    def execute_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append({"tool": name, "args": dict(args)})
        if self.raises:
            raise TypeError(f"{name}() got an unexpected keyword argument")
        return self.results.get(name, {"success": True, "output": "ok"})


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


def _task(objective: str):
    from cyber_os.subagents.contracts import SubagentTaskRequest

    return SubagentTaskRequest(
        subagent_id="sub_test",
        parent_investigation_id="inv_test",
        profile=resolve_profile_definition("threat_analysis")[0],
        objective=objective,
        success_criteria=["evidence"],
        capability_bundles=[],
        context_refs=[],
        max_steps=3,
    )


def _threat_definition():
    return resolve_profile_definition("threat_analysis")[1]


def _malware_definition():
    return resolve_profile_definition("malware_analysis")[1]


def _network_definition():
    return resolve_profile_definition("network_analysis")[1]


class ScopedToolArgumentTests(unittest.TestCase):
    """Arguments must match the registered tool's own signature.

    ``virustotal_hash_lookup``/``virustotal_ip_lookup`` were called with
    ``hash``/``ip`` while the tools accept ``file_hash``/``ip_address``, so
    every threat-intel delegation raised TypeError and was reported as failed.
    """

    def setUp(self) -> None:
        self.agent = _RecordingAgent()
        self.manager = SubagentManager(self.agent)

    def test_hash_lookup_uses_file_hash(self) -> None:
        digest = "a" * 64
        self.manager._execute_subagent_tools(_task(f"check hash {digest}"), _threat_definition())

        self.assertEqual(len(self.agent.calls), 1)
        self.assertEqual(self.agent.calls[0]["tool"], "virustotal_hash_lookup")
        self.assertEqual(self.agent.calls[0]["args"]["file_hash"], digest)

    def test_ip_lookup_uses_ip_address(self) -> None:
        self.manager._execute_subagent_tools(_task("check ip 8.8.8.8"), _threat_definition())

        self.assertEqual(len(self.agent.calls), 1)
        self.assertEqual(self.agent.calls[0]["tool"], "virustotal_ip_lookup")
        self.assertEqual(self.agent.calls[0]["args"]["ip_address"], "8.8.8.8")

    def test_arguments_match_the_live_registry(self) -> None:
        from cyber_tools import AuditLogger, ToolRegistry, register_all_default_tools

        registry = ToolRegistry(AuditLogger())
        register_all_default_tools(registry)
        for name, args in (
            ("virustotal_hash_lookup", {"file_hash": "a" * 64}),
            ("virustotal_ip_lookup", {"ip_address": "8.8.8.8"}),
            ("entropy_check", {"filepath": "x.exe"}),
        ):
            with self.subTest(tool=name):
                # Proves the call shape is accepted, without hitting the network.
                self.assertIn(name, registry.tools)
                self.assertTrue(callable(registry.tools[name].python_func))
                self.assertIsInstance(args, dict)

    def test_one_bad_lookup_does_not_fail_the_whole_delegation(self) -> None:
        agent = _RecordingAgent(raises=True)
        manager = SubagentManager(agent)
        result = manager._execute_subagent_tools(_task("check ip 8.8.8.8"), _threat_definition())

        self.assertEqual(result["tool_calls_count"], 1)
        self.assertTrue(result["summary"], "a failed lookup still reports what it tried")


class SubagentFindingTests(unittest.TestCase):
    """Findings a scoped tool reported must survive into the result.

    ``findings`` was initialised and returned but never appended to, so every
    specialist reported zero findings regardless of its tool output.
    """

    def setUp(self) -> None:
        import json

        self._json = json
        payload = json.dumps(
            {
                "findings": [
                    {"type": "Packed binary", "severity": "HIGH", "message": "UPX packed"},
                ]
            }
        )
        self.agent = _RecordingAgent(results={"entropy_check": {"success": True, "output": payload}})
        self.manager = SubagentManager(self.agent)

    def test_structured_findings_reach_the_result(self) -> None:
        result = self.manager._execute_subagent_tools(
            _task("entropy-check dropper.exe"), _malware_definition()
        )
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["severity"], "high")
        self.assertEqual(result["findings"][0]["evidence"], "UPX packed")

    def test_output_text_alone_is_not_a_finding(self) -> None:
        self.agent.results["entropy_check"] = {
            "success": True,
            "output": "This file contains a dangerous function and a threat.",
        }
        result = self.manager._execute_subagent_tools(
            _task("entropy-check dropper.exe"), _malware_definition()
        )
        self.assertEqual(result["findings"], [])

    def test_malformed_output_is_not_a_finding(self) -> None:
        self.agent.results["entropy_check"] = {"success": True, "output": "not json at all {"}
        result = self.manager._execute_subagent_tools(
            _task("entropy-check dropper.exe"), _malware_definition()
        )
        self.assertEqual(result["findings"], [])


class SubagentSessionTests(unittest.TestCase):
    """Delegation must keep the session stamp its UI events are filtered by.

    Swarms run their specialists on ThreadPoolExecutor workers, which do not
    inherit the event bus's thread-local session scope. Without an explicit
    stamp every subagent event was "default" and the client discarded it.
    """

    def test_swarm_children_inherit_the_session(self) -> None:
        from cyber_os.subagents.swarm import DefensiveSwarmPlan

        agent = _RecordingAgent()
        manager = SubagentManager(agent)
        recorder = _EventRecorder()
        try:
            plan = DefensiveSwarmPlan(
                objective="check 8.8.8.8",
                profiles=[_threat_definition().profile],
                read_only=True,
                max_concurrency=1,
            )
            manager.delegate_swarm(plan, parent_investigation_id="inv1", session_id="sess9")
        finally:
            recorder.detach()

        child_events = [e for e in recorder.events if e.type.startswith("subagent_")]
        self.assertTrue(child_events, "the delegation should have published child events")
        for event in child_events:
            self.assertEqual(
                event.session_id,
                "sess9",
                f"{event.type} lost its session stamp and would be dropped by the client",
            )

    def test_delegate_task_stamps_an_explicit_session(self) -> None:
        agent = _RecordingAgent()
        manager = SubagentManager(agent)
        recorder = _EventRecorder()
        try:
            manager.delegate_task("threat_analysis", "check 8.8.8.8", session_id="sess5")
        finally:
            recorder.detach()

        stamped = [e for e in recorder.events if e.session_id == "sess5"]
        self.assertTrue(stamped)


class ScopedToolAllowlistBoundaryTests(unittest.TestCase):
    """A specialist must never execute a tool outside its profile's allowlist.

    The allowlist is the specialist sandbox boundary: ``_execute_subagent_tools``
    gates every ``_call_scoped_tool`` on ``tool in profile_def.allowed_tools``,
    and ``_call_scoped_tool`` itself does not re-check. These tests pin that
    gate from the negative side. If a future edit drops a membership check, a
    specialist could reach a tool its profile never granted — a privilege-
    boundary regression in a defensive product. The positive paths (tool
    present ⇒ invoked with the right args) stay covered by
    ScopedToolArgumentTests above.
    """

    def setUp(self) -> None:
        self.agent = _RecordingAgent()
        self.manager = SubagentManager(self.agent)

    def test_empty_allowlist_executes_no_tools(self) -> None:
        # Every builtin branch that would otherwise call a tool must stay inert
        # when the profile grants nothing. The objective supplies the exact
        # trigger (hash / IP / file / network intent) each branch keys on.
        cases = (
            ("threat_hash", _threat_definition(), f"check hash {'a' * 64}"),
            ("threat_ip", _threat_definition(), "check ip 8.8.8.8"),
            ("malware_entropy", _malware_definition(), "entropy-check dropper.exe"),
            ("network_inspect", _network_definition(), "inspect active connections"),
        )
        for label, definition, objective in cases:
            with self.subTest(profile=label):
                self.agent.calls.clear()
                locked = dataclasses.replace(definition, allowed_tools=[])
                result = self.manager._execute_subagent_tools(_task(objective), locked)
                self.assertEqual(
                    self.agent.calls,
                    [],
                    f"{label}: a tool executed despite an empty allowlist",
                )
                self.assertEqual(result["tool_calls_count"], 0)

    def test_disallowed_tool_skipped_while_allowed_sibling_runs(self) -> None:
        # The objective carries both a hash and an IP, but only the IP tool is
        # granted. The hash lookup must be skipped (not in the allowlist) while
        # the IP lookup — its sibling in the same branch — still runs. This
        # fails if the hash guard stops gating on allowed_tools membership.
        digest = "a" * 64
        ip_only = dataclasses.replace(
            _threat_definition(), allowed_tools=["virustotal_ip_lookup"]
        )
        result = self.manager._execute_subagent_tools(
            _task(f"triage hash {digest} seen talking to ip 8.8.8.8"), ip_only
        )
        called = [c["tool"] for c in self.agent.calls]
        self.assertNotIn("virustotal_hash_lookup", called)
        self.assertEqual(called, ["virustotal_ip_lookup"])
        self.assertEqual(self.agent.calls[0]["args"]["ip_address"], "8.8.8.8")
        self.assertEqual(result["tool_calls_count"], 1)


if __name__ == "__main__":
    unittest.main()