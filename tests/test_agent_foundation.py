import tempfile
import unittest

from cyber_os.investigation_state import InvestigationState
from cyber_os.tool_orchestrator import ToolOrchestrator
from ui.event_bus import AgentEvent


class AgentFoundationTests(unittest.TestCase):
    def test_events_have_unique_ids_and_round_trip(self):
        first = AgentEvent(type="test")
        second = AgentEvent(type="test")
        self.assertNotEqual(first.event_id, second.event_id)
        self.assertEqual(first.correlation_id, first.event_id)
        self.assertEqual(first.to_dict()["event_id"], first.event_id)

    def test_investigation_state_persists_events_atomically(self):
        with tempfile.TemporaryDirectory() as root:
            store = InvestigationState(root)
            state = store.create("inspect endpoint")
            event = AgentEvent(type="investigation.started", investigation_id=state["investigation_id"])
            self.assertTrue(store.append_event(state["investigation_id"], event.to_dict()))
            loaded = store.load(state["investigation_id"])
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["events"][0]["type"], event.type)

    def test_tool_manifest_contains_safety_metadata(self):
        orchestrator = ToolOrchestrator()
        manifest = orchestrator.tool_manifest()
        defender = next(item for item in manifest if item["name"] == "windows_defender_scan")
        self.assertIn("risk_level", defender)
        self.assertIn("requires_admin", defender)
        self.assertIn("environments", defender)

    def test_planner_rejects_unknown_tools(self):
        orchestrator = ToolOrchestrator()
        orchestrator.llm.chat_json = lambda **_: {"tool": "not_registered", "arguments": {}}
        result = type("IntentResult", (), {"intent": type("Intent", (), {"value": "analysis"})()})()
        self.assertIsNone(orchestrator._select_tool("inspect the endpoint", result))


if __name__ == "__main__":
    unittest.main()
