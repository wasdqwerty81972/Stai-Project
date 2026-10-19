"""MCP tool discovery must not advertise capabilities the executor cannot use."""

from __future__ import annotations

import os
import sys
import types
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "cyber_soc_engine"))

from core.integrations.mcp import registry as registry_module  # noqa: E402


class MCPRegistryLiveStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = registry_module.MCPRegistry()
        self.cached_tools = {"playwright": [{"name": "open_page", "inputSchema": {}}]}

    def _client_module(self, client):
        module = types.ModuleType("core.integrations.mcp.client")
        module.process_mcp_client = lambda: client
        return module

    def test_disk_cache_is_not_advertised_without_process_client(self) -> None:
        with (
            patch.object(registry_module, "_cached_tools", return_value=self.cached_tools),
            patch.dict(sys.modules, {"core.integrations.mcp.client": self._client_module(None)}),
        ):
            registered = registry_module.populate_from_cache(self.registry)

        self.assertEqual(registered, 0)
        self.assertEqual(self.registry.get_tool_names(), [])

    def test_unreadable_connection_state_fails_closed(self) -> None:
        client = type("Client", (), {
            "tools_cache": self.cached_tools,
            "get_connection_status": lambda self: (_ for _ in ()).throw(RuntimeError("offline")),
        })()
        with (
            patch.object(registry_module, "_cached_tools", return_value=self.cached_tools),
            patch.dict(sys.modules, {"core.integrations.mcp.client": self._client_module(client)}),
        ):
            registered = registry_module.populate_from_cache(self.registry)

        self.assertEqual(registered, 0)
        self.assertEqual(self.registry.get_tool_names(), [])

    def test_only_live_tools_from_connected_server_are_advertised(self) -> None:
        client = type("Client", (), {
            "tools_cache": {"playwright": [{"name": "current_page", "inputSchema": {}}]},
            "get_connection_status": lambda self: {"playwright": True},
        })()
        with (
            patch.object(registry_module, "_cached_tools", return_value=self.cached_tools),
            patch.dict(sys.modules, {"core.integrations.mcp.client": self._client_module(client)}),
        ):
            registered = registry_module.populate_from_cache(self.registry)

        self.assertEqual(registered, 1)
        self.assertEqual(self.registry.get_tool_names(), ["playwright_current_page"])


if __name__ == "__main__":
    unittest.main()
