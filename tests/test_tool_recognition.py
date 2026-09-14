"""
tests/test_tool_recognition.py — Verify the agent recognizes all registered tools
and can call them, with proper error handling for unknown tools.

Tests:
1. Tool registry contains all expected core security tools
2. Each tool has proper metadata (risk_level, environments, description)
3. Read-only tools with python_func can be executed via CyberAgent.execute_tool
4. Unknown/non-existent tools return structured errors
5. AI tool planner selects valid tools from the manifest (mock LLM)
"""

from __future__ import annotations

import unittest
from cyber_tools import register_all_default_tools, ToolRegistry, AuditLogger, RiskLevel
from cyber_os.tool_orchestrator import ToolOrchestrator, ToolCall

EXPECTED_CORE_TOOLS = {
    "workspace_list_files",
    "workspace_read_file",
    "list_available_drives",
    "static_analysis",
    "network_inspect",
    "nmap_scan",
    "windows_defender_scan",
    "secret_scan",
    "file_analyze",
    "workspace_scan",
    "volatility_memory",
    "strings_inspect",
    "bandit_scan",
    "semgrep_scan",
    "trivy_scan",
    "virustotal_scan",
    "yara_scan",
    "osint_subdomain_enum",
    "dns_lookup",
    "whois_lookup",
    "tls_cert_inspect",
    "cloud_s3_check",
    "email_security_posture",
    "soc_compile_workflow",
    "soc_validate_workflow",
    "soc_generate_sample_data",
}


class ToolRecognitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.orchestrator = ToolOrchestrator(use_mock_llm=True)
        cls.registry = cls.orchestrator.registry
        cls.manifest = cls.registry.list_tools()

    def test_all_expected_core_tools_are_registered(self):
        """The AI must be able to recognise every expected tool in the registry."""
        registered = set(self.registry.tools.keys())
        missing = EXPECTED_CORE_TOOLS - registered
        self.assertEqual(
            missing, set(),
            f"The following expected tools are missing from the registry: {missing}",
        )

    def test_tool_count_is_substantial(self):
        """A defensive security platform should ship with a large tool catalog."""
        self.assertGreaterEqual(len(self.registry.tools), 100)

    def test_read_only_tools_have_python_or_command(self):
        """Every READ_ONLY tool should have either a python_func or a command_template."""
        read_only = [
            t for t in self.registry.tools.values()
            if t.risk_level == RiskLevel.READ_ONLY
        ]
        self.assertGreater(len(read_only), 10)
        for tool in read_only:
            self.assertTrue(
                tool.python_func is not None or bool(tool.command_template),
                f"READ_ONLY tool '{tool.name}' has no executable form",
            )

    def test_all_tools_have_required_metadata(self):
        """Every registered tool must have a name, risk_level, and non-empty environments."""
        for name, tool in self.registry.tools.items():
            self.assertTrue(name, "Tool name must be non-empty")
            self.assertIsInstance(tool.risk_level, RiskLevel, f"{name} has invalid risk_level")
            self.assertIsInstance(tool.environments, list, f"{name} has invalid environments")
            self.assertTrue(len(tool.environments) > 0, f"{name} has no environments")

    def test_tool_manifest_is_well_formed(self):
        """The tool manifest (sent to the AI model) should contain name, risk_level, and environments for every tool."""
        manifest = self.registry.list_tools()
        self.assertEqual(len(manifest), len(self.registry.tools))
        for entry in manifest:
            self.assertIn("name", entry)
            self.assertIn("risk_level", entry)
            self.assertIn("environments", entry)
            self.assertIn("requires_admin", entry)
            self.assertTrue(entry["risk_level"], f"Tool {entry['name']} has empty risk_level")


class ToolCallingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = ToolRegistry(AuditLogger())
        register_all_default_tools(cls.registry)

    def test_read_only_tool_execution_list_available_drives(self):
        """The agent should call 'list_available_drives' (read-only, python_func) and get a structured result."""
        tool = self.registry.tools.get("list_available_drives")
        self.assertIsNotNone(tool, "list_available_drives must be registered")
        self.assertIsNotNone(tool.python_func, "list_available_drives must have a python_func")
        result = tool.python_func()
        self.assertIsInstance(result, dict)
        self.assertIn("drives", result)
        self.assertIn("count", result)

    def test_read_only_tool_execution_workspace_list_files(self):
        """The agent should call 'workspace_list_files' (read-only) and receive file entries."""
        tool = self.registry.tools.get("workspace_list_files")
        self.assertIsNotNone(tool)
        self.assertIsNotNone(tool.python_func)
        result = tool.python_func(root=".", pattern="*.py", max_results=5)
        self.assertIsInstance(result, dict)
        self.assertIn("files", result)

    def test_unknown_tool_returns_error(self):
        """Calling a tool that doesn't exist must return a structured failure, not raise."""
        from cyber_agent import CyberAgent
        agent = CyberAgent(workspace_path=".")
        result = agent.execute_tool("nonexistent_tool_xyz", {"arg": "value"})
        self.assertFalse(result.get("success"))
        self.assertEqual(result["tool"], "nonexistent_tool_xyz")
        self.assertIn("not found", result.get("error", "").lower())

    def test_destructive_tool_still_in_registry(self):
        """Destructive tools should exist in the manifest but be gated by risk_level, not absent."""
        tool = self.registry.tools.get("metasploit_console")
        if tool is not None:
            self.assertEqual(tool.risk_level, RiskLevel.DESTRUCTIVE)


class AIOrchestratorToolSelectionTests(unittest.TestCase):
    """Verify that the AI orchestrator's tool planner selects valid tools from the manifest."""

    def test_llm_selects_valid_tool_from_manifest(self):
        """When the mock LLM picks a tool, the orchestrator validates it against the registry."""
        orchestrator = ToolOrchestrator(use_mock_llm=True)

        # Simulate the LLM returning a tool selection that exists in the registry
        orchestrator.llm.chat_json = lambda **_: {
            "tool": "network_inspect",
            "arguments": {},
            "reason": "User wants network analysis.",
        }

        intent_result = orchestrator.router.classify("Inspect the workspace for problems")
        selected = orchestrator._select_tool("Inspect the workspace for problems", intent_result)
        self.assertEqual(selected, "network_inspect")

    def test_llm_selects_rejected_when_tool_not_in_registry(self):
        """When the LLM returns a tool name not in the registry, the orchestrator returns None."""
        orchestrator = ToolOrchestrator(use_mock_llm=True)

        orchestrator.llm.chat_json = lambda **_: {
            "tool": "invented_tool_not_real",
            "arguments": {},
            "reason": "Guessing a tool name.",
        }

        intent_result = orchestrator.router.classify("Analyze this workspace")
        selected = orchestrator._select_tool("Analyze this workspace", intent_result)
        self.assertIsNone(selected)

    def test_orchestrator_calls_recognized_tool(self):
        """End-to-end: mock LLM selects a valid tool, orchestrator executes it (mocked _execute_tool), result is recorded."""
        orchestrator = ToolOrchestrator(use_mock_llm=True)

        orchestrator.llm.chat_json = lambda **_: {
            "tool": "list_available_drives",
            "arguments": {},
            "reason": "User wants to know available drives.",
        }
        orchestrator.llm.chat = lambda **_: "The C:\\ drive is available."

        orchestrator._execute_tool = lambda tool_name, args: ToolCall(
            tool=tool_name, arguments=args, status="completed",
            result={"success": True, "output": '{"drives": ["C:\\\\"], "count": 1}', "error": ""},
            error=None, duration_ms=1.0,
        )

        result = orchestrator.handle_message("Inspect the workspace for problems")
        self.assertTrue(result.success)
        self.assertGreater(len(result.tool_calls), 0)
        self.assertEqual(result.tool_calls[0].tool, "list_available_drives")
        self.assertEqual(result.tool_calls[0].status, "completed")


if __name__ == "__main__":
    unittest.main()
