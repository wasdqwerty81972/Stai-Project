"""
tests/test_incident_report_evidence.py — an incident report must not invent evidence.

``generate_incident_report`` used to open the relative path "audit_log.json",
which resolved against the current working directory and so missed the real log
whenever the agent was launched from anywhere but the project root. On any read
failure it substituted::

    logs = [{"action": "system_audit", "status": "COMPLETED"}]

and passed that to the model, which then wrote an executive incident report
describing an audit that had never run. A fabricated all-clear is the worst
possible output for a security tool: it is indistinguishable from a real one.

``ResponseEngine`` had the mirror-image problem — it called
``audit_logger.log_action``, which AuditLogger does not define, under a bare
``except Exception: pass``. The only caller passes ``audit_logger=None``, which
is what kept the mismatch from ever surfacing.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cyber_tools import AuditLogger  # noqa: E402


class IncidentReportEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from cyber_agent import CyberAgent

        cls._agent_cls = CyberAgent

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = os.path.join(self._dir.name, "audit.jsonl")

        self.agent = self._agent_cls(workspace_path=self._dir.name)
        self.agent.audit_logger = AuditLogger(self.path)

        self.tool_calls: list = []

        def record(tool_name: str, args: dict):
            self.tool_calls.append((tool_name, args))
            return {"success": True, "output": "executive summary text"}

        self.agent.execute_tool = record  # type: ignore[method-assign]

    def test_an_empty_audit_trail_yields_no_report_at_all(self) -> None:
        result = self.agent.generate_incident_report()

        self.assertFalse(result["success"])
        self.assertIn("no evidence", result["error"].lower())
        self.assertEqual(
            self.tool_calls, [], "the model must not be asked to summarise nothing"
        )

    def test_a_failed_read_does_not_fabricate_a_completed_audit(self) -> None:
        # Point the logger at a path that cannot be read, the exact condition
        # that used to mint the fake "system_audit COMPLETED" event.
        self.agent.audit_logger.log_path = os.path.join(self.path, "nope", "audit.jsonl")

        result = self.agent.generate_incident_report()

        self.assertFalse(result["success"])
        self.assertEqual(self.tool_calls, [])
        blob = json.dumps(result)
        self.assertNotIn("system_audit", blob)
        self.assertNotIn("COMPLETED", blob)

    def test_the_report_is_built_from_the_real_audit_events(self) -> None:
        for n in range(7):
            self.agent.audit_logger.log_event(f"tool_execution_{n}", {"n": n})

        result = self.agent.generate_incident_report()

        self.assertEqual(len(self.tool_calls), 1)
        tool_name, args = self.tool_calls[0]
        self.assertEqual(tool_name, "ai_incident_summary")
        events = json.loads(args["events_json"])
        # The five most recent, in order, and nothing invented.
        self.assertEqual(
            [e["action"] for e in events],
            ["tool_execution_2", "tool_execution_3", "tool_execution_4",
             "tool_execution_5", "tool_execution_6"],
        )
        self.assertNotIn("warning", result)

    def test_the_log_location_follows_the_logger_not_the_working_directory(self) -> None:
        # The old hardcoded relative open() meant the report silently described
        # a different (or absent) file than the one the agent was writing to.
        self.agent.audit_logger.log_event("tool_execution", {"target": "10.0.0.1"})
        original_cwd = os.getcwd()
        os.chdir(self._dir.name)
        try:
            self.agent.generate_incident_report()
        finally:
            os.chdir(original_cwd)

        self.assertEqual(len(self.tool_calls), 1)
        events = json.loads(self.tool_calls[0][1]["events_json"])
        self.assertEqual(events[0]["details"]["target"], "10.0.0.1")

    def test_an_incomplete_trail_is_declared_on_the_report(self) -> None:
        self.agent.audit_logger.log_event("tool_execution", {"real": True})
        # Force one dropped write so the trail is genuinely incomplete.
        good_path = self.agent.audit_logger.log_path
        self.agent.audit_logger.log_path = os.path.join(good_path, "nope", "x.jsonl")
        self.assertFalse(self.agent.audit_logger.log_event("lost", {}))
        self.agent.audit_logger.log_path = good_path

        result = self.agent.generate_incident_report()

        self.assertEqual(len(self.tool_calls), 1)
        self.assertIn("warning", result)
        self.assertIn("incomplete", result["warning"].lower())
        self.assertFalse(result["audit_health"]["complete"])
        self.assertEqual(result["audit_health"]["dropped_events"], 1)


class ResponseEngineAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.logger = AuditLogger(os.path.join(self._dir.name, "audit.jsonl"))

    def _engine(self):
        from cyber_os.response_engine import ResponseEngine

        return ResponseEngine(policy_engine=None, audit_logger=self.logger)

    def test_a_response_action_reaches_the_audit_log(self) -> None:
        engine = self._engine()
        # An unknown action type still has to be audited -- an attempted
        # response is exactly the thing a forensic trail needs to record.
        result = engine.execute_action("not_a_real_action", target="10.0.0.1",
                                       reason="unit test", approved=True)

        self.assertIs(result.audited, True, "the action was not written to the audit log")
        events = self.logger.read_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["action"], "response_not_a_real_action")
        self.assertEqual(events[0]["details"]["actor"], "ResponseEngine")
        self.assertEqual(events[0]["details"]["target"], "10.0.0.1")
        self.assertEqual(events[0]["details"]["approval"], "USER_APPROVED")
        self.assertEqual(events[0]["details"]["action_id"], result.action_id)

    def test_an_unaudited_action_is_visible_on_the_result(self) -> None:
        engine = self._engine()
        self.logger.log_path = os.path.join(self.logger.log_path, "nope", "x.jsonl")

        result = engine.execute_action("not_a_real_action", target="10.0.0.1")

        self.assertIs(result.audited, False)
        self.assertIs(result.to_dict()["audited"], False)

    def test_no_logger_configured_is_distinct_from_a_failed_write(self) -> None:
        from cyber_os.response_engine import ResponseEngine

        result = ResponseEngine().execute_action("not_a_real_action", target="10.0.0.1")
        self.assertIsNone(result.audited)


if __name__ == "__main__":
    unittest.main()
