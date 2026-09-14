"""
tests/test_hackerai_integration.py — Integration tests for HackerAI UI and API server.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch


class TestHackerAIIntegration(unittest.TestCase):
    def test_api_server_imports(self):
        import ui.api_server as server

        self.assertTrue(hasattr(server, "app"))
        self.assertTrue(hasattr(server, "chat_history"))
        self.assertTrue(hasattr(server, "active_connections"))

    def test_websocket_broadcast(self):
        import asyncio
        import ui.api_server as server

        mock_ws = MagicMock()
        server.active_connections.append(mock_ws)

        payload = {"type": "test", "message": "hello"}

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(server._broadcast(payload))
        finally:
            loop.close()

        mock_ws.send_text.assert_called_once_with(
            unittest.mock.ANY
        )

    def test_subagent_registry_lists_all_profiles(self):
        from subagents.registry import list_all_subagents

        subagents = list_all_subagents()
        self.assertGreaterEqual(len(subagents), 10)

        profiles = [s["profile"] for s in subagents]
        self.assertIn("threat_analysis", profiles)
        self.assertIn("malware_analysis", profiles)
        self.assertIn("incident_investigation", profiles)

    def test_unified_subagent_manager_delegates_task(self):
        from subagents.manager import UnifiedSubagentManager
        from subagents.contracts import SubagentProfile

        manager = UnifiedSubagentManager(agent=MagicMock())
        result = manager.delegate_task(
            profile_name=SubagentProfile.THREAT_ANALYSIS,
            objective="Test threat intelligence assessment",
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.profile, "threat_analysis")
        self.assertIn(result.verdict, ["confirmed", "completed", "inconclusive"])


if __name__ == "__main__":
    unittest.main()
