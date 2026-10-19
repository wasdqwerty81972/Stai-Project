"""
tests/test_protection_escalation_boundary.py

Pins the Level 2 agent-escalation SAFETY boundary that exists in-tree today:
the disruptive-response approval + audit path in ``CyberOSEngine``.

The STAI Windows protection design
(docs/superpowers/specs/2026-10-12-stai-custom-windows-protection-design.md,
"Level 2: agent investigation and response") and the agent-escalation plan
(docs/superpowers/plans/2026-10-12-stai-agent-escalation.md, Task 3 + Review
Focus) require that:

  * the agent cannot change the Level 1 verdict or directly contain anything;
  * any disruptive follow-up (terminate process, block IP, isolate host) goes
    through the EXISTING typed human-approval path -- never free-form shell,
    never straight from agent recommendation text;
  * an unknown approval id or a missing approver executes NO action;
  * every proposed and resolved action is audited with its outcome.

The Phase-2 triage modules the plan creates (``cyber_os/protection/triage.py``
and ``cyber_os/protection/agent_triage.py``) are NOT implemented yet, so these
tests do not exercise a triage contract. Instead they pin the approval/audit
seam that Task 3 Step 3 says to *reuse*
(``CyberOSEngine.resolve_response_approval`` / ``_execute_response``), so that a
future escalation wiring cannot regress it.

Fully offline and deterministic: no network, no real LLM, no sleeps, and the
engine is never ``start()``-ed (no sensor threads). The two OS-containment
helpers are replaced with sentinels that *record* calls and return ``False``,
so a bypass of the approval gate fails the test instead of shelling out to
netsh/taskkill.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from cyber_os.engine import CyberOSEngine, ThreatAlert
from ui.event_bus import event_bus


def _alert(summary: str, *, event_id: str, threat_score: int = 9) -> ThreatAlert:
    """Build a high-severity alert that stands in for an escalated detection."""
    return ThreatAlert(
        timestamp="2026-10-12T00:00:00+00:00",
        alert_type="protection_detection",
        severity="CRITICAL",
        mitre_technique="T1204",
        technique_name="User Execution",
        summary=summary,
        evidence=["inert test detection"],
        ai_reasoning="unit test alert; no real telemetry",
        blast_radius="n/a",
        threat_score=threat_score,
        recommended_actions=["Isolate host"],
        event_id=event_id,
    )


class ProtectionEscalationBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        # Construct the engine inside a throwaway cwd so its SQLite sensor queue
        # (cyber_db/...) lands in the temp dir, exactly like test_endpoint_pipeline.
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        _cwd = os.getcwd()
        os.chdir(self._dir.name)
        self.addCleanup(lambda: os.chdir(_cwd))

        # "missing.json" does not exist -> deterministic default config.
        self.engine = CyberOSEngine(config_path="missing.json")

        # Hard guard: no disruptive OS action may run during these tests.
        self.block_calls: list = []
        self.kill_calls: list = []
        self.engine._block_ip = lambda ip, **kw: (self.block_calls.append(ip), False)[1]  # type: ignore[assignment]
        self.engine._terminate_process = lambda pid, **kw: (self.kill_calls.append(pid), False)[1]  # type: ignore[assignment]

    def _resolved_events(self):
        return event_bus.get_history("response_approval_resolved")

    def _required_events(self):
        return event_bus.get_history("response_approval_required")

    def _assert_nothing_executed(self) -> None:
        self.assertEqual(self.block_calls, [], "an IP block ran without approval")
        self.assertEqual(self.kill_calls, [], "a process kill ran without approval")

    # ------------------------------------------------------------------
    # Unknown approval id -> execute no action (plan Review Focus).
    # ------------------------------------------------------------------
    def test_unknown_approval_id_executes_no_response(self) -> None:
        actions = self.engine.resolve_response_approval("response-doesnotexist", True, "analyst")
        self.assertEqual(actions, [])
        self._assert_nothing_executed()

    # ------------------------------------------------------------------
    # Approval with no named approver -> execute no action.
    # ------------------------------------------------------------------
    def test_missing_approver_executes_no_response(self) -> None:
        approval_id = self.engine._request_response_approval(_alert("suspicious host activity", event_id="A1"))
        self.assertTrue(approval_id)
        actions = self.engine.resolve_response_approval(approval_id, True, "")
        self.assertEqual(actions, [])
        self._assert_nothing_executed()
        # The approval was consumed as denied, not left dangling as approved.
        self.assertFalse(self.engine.has_pending_response_approval(approval_id))

    # ------------------------------------------------------------------
    # Explicit human denial -> execute no action.
    # ------------------------------------------------------------------
    def test_denied_approval_executes_no_response(self) -> None:
        approval_id = self.engine._request_response_approval(_alert("suspicious host activity", event_id="A2"))
        actions = self.engine.resolve_response_approval(approval_id, False, "analyst")
        self.assertEqual(actions, [])
        self._assert_nothing_executed()

    # ------------------------------------------------------------------
    # Agent recommendation text is NOT an execution path: an alert whose
    # summary reads like Level 2 advice ("block ... terminate the process")
    # must not run anything without a resolved approval. Instead the engine
    # must open a fresh human-approval request.
    # ------------------------------------------------------------------
    def test_agent_recommendation_text_does_not_execute_a_response(self) -> None:
        alert = _alert(
            "Agent recommends: block the source and terminate the process now",
            event_id="A3",
        )
        pending_before = len(self.engine.get_pending_response_approvals())
        actions = self.engine._execute_response(alert)  # no approval_id supplied
        self.assertEqual(actions, [])
        self._assert_nothing_executed()
        # A disruptive action request was raised for a human instead of acting.
        self.assertEqual(len(self.engine.get_pending_response_approvals()), pending_before + 1)

    # ------------------------------------------------------------------
    # The disruptive-action request is published for human approval and
    # registered in the approval engine (dedup holds).
    # ------------------------------------------------------------------
    def test_disruptive_request_is_published_and_registered_for_human_approval(self) -> None:
        before = len(self._required_events())
        approval_id = self.engine._request_response_approval(_alert("inert test detection", event_id="A4"))
        self.assertTrue(approval_id.startswith("response-"))
        self.assertTrue(self.engine.has_pending_response_approval(approval_id))

        required = self._required_events()
        self.assertEqual(len(required), before + 1)
        evt = required[-1]
        self.assertIs(evt.data.get("disruptive_actions_require_human_approval"), True)
        self.assertEqual(evt.data.get("approval_id"), approval_id)
        # Re-registering the same pending request is refused (no duplicate gate).
        self.assertFalse(self.engine.approval_engine.register_pending_request(approval_id))

    # ------------------------------------------------------------------
    # An approved resolution is audited with its outcome, and -- with no
    # IP/PID target in the alert -- still runs nothing disruptive.
    # ------------------------------------------------------------------
    def test_approved_resolution_is_audited_with_outcome(self) -> None:
        before = len(self._resolved_events())
        approval_id = self.engine._request_response_approval(_alert("benign inert test detection", event_id="A5"))
        actions = self.engine.resolve_response_approval(approval_id, True, "analyst-1")

        self.assertEqual(actions, [])  # no supported containment target in summary
        self._assert_nothing_executed()

        resolved = self._resolved_events()
        self.assertEqual(len(resolved), before + 1)
        evt = resolved[-1]
        self.assertEqual(evt.data.get("approval_id"), approval_id)
        self.assertEqual(evt.data.get("approved_by"), "analyst-1")
        self.assertIn(evt.status, {"completed", "no_action"})
        # The approval is single-use: it is no longer pending after resolution.
        self.assertFalse(self.engine.has_pending_response_approval(approval_id))


if __name__ == "__main__":
    unittest.main()
