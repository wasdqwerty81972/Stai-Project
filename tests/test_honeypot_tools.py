import unittest
from unittest import mock

import cyber_tools


class HoneypotManagerTests(unittest.TestCase):
    def test_start_defaults_to_loopback_and_waits_until_listener_is_ready(self):
        manager = cyber_tools.HoneypotManager()
        sock = mock.MagicMock()
        sock.accept.side_effect = cyber_tools.socket.timeout
        with mock.patch.object(cyber_tools.socket, "socket", return_value=sock):
            result = manager.start()

        self.assertEqual(result["status"], "started")
        self.assertEqual(result["host"], "127.0.0.1")
        self.assertEqual(result["port"], 2222)
        sock.bind.assert_called_once_with(("127.0.0.1", 2222))
        self.assertTrue(manager.status()["running"])
        self.assertEqual(manager.start(), {
            "status": "already_running", "host": "127.0.0.1", "port": 2222
        })
        manager.stop()

    def test_invalid_bind_configuration_is_rejected_before_socket_creation(self):
        manager = cyber_tools.HoneypotManager()
        with mock.patch.object(cyber_tools.socket, "socket") as make_socket:
            for host, port in (("not-an-ip", 2222), ("127.0.0.1", 0), ("127.0.0.1", 65536)):
                with self.subTest(host=host, port=port), self.assertRaises(ValueError):
                    manager.start(host=host, port=port)
        make_socket.assert_not_called()

    def test_bind_failure_is_returned_as_failure_and_status_stays_stopped(self):
        manager = cyber_tools.HoneypotManager()
        sock = mock.MagicMock()
        sock.bind.side_effect = OSError("address unavailable")
        with mock.patch.object(cyber_tools.socket, "socket", return_value=sock):
            result = manager.start()
        self.assertEqual(result["status"], "failed")
        self.assertIn("address unavailable", result["error"])
        self.assertFalse(manager.status()["running"])
        self.assertIn("address unavailable", manager.status()["error"])

    def test_honeypot_tools_are_gated_as_system_changes(self):
        class Registry:
            tools = {}

            def register_tool(self, tool):
                self.tools[tool.name] = tool

        registry = Registry()
        cyber_tools._register_honeypot_tools(registry)
        for name in ("start_honeypot", "stop_honeypot"):
            self.assertEqual(registry.tools[name].risk_level, cyber_tools.RiskLevel.MODIFIES_SYSTEM)


if __name__ == "__main__":
    unittest.main()
