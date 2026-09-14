import json
import unittest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from cyber_os.nemo_agent_toolkit import NeMoAgentToolkitBridge
from cyber_os.tool_orchestrator import ToolOrchestrator
from cyber_os.intent_router import IntentType, IntentRouter
from cyber_os.investigation_state import InvestigationState


class NemoIntegrationTests(unittest.TestCase):
    def test_bridge_is_optional_and_preserves_native_ui(self):
        bridge = NeMoAgentToolkitBridge(
            [{"name": "network_inspect", "risk_level": "read_only"}], "."
        )
        status = bridge.status()
        self.assertEqual(status["package"], "nvidia-nat")
        self.assertEqual(status["native_ui"], "PySide6")
        self.assertEqual(status["tool_count"], 1)

    def test_orchestrator_exposes_nat_status(self):
        orchestrator = ToolOrchestrator()
        status = orchestrator.nat_status()
        self.assertIn("available", status)
        self.assertEqual(status["tool_count"], len(orchestrator.tool_manifest()))
        self.assertTrue(orchestrator.nat.workflow_config()["security"]["allowlist_enforced"])

    def test_intermediate_step_becomes_thread_event(self):
        class Step:
            name = "Tool planner"
            status = "completed"
            step_id = "step-1"
            parent_id = "root"
            step_type = "tool"
            output = {"tool": "network_inspect"}

        bridge = NeMoAgentToolkitBridge([], ".")
        event = bridge.publish_intermediate_step(Step(), "inv-1")
        self.assertEqual(event.type, "nat_step_completed")
        self.assertEqual(event.investigation_id, "inv-1")
        self.assertEqual(event.source, "nemo_agent_toolkit")
        self.assertEqual(event.data["step_id"], "step-1")

    def test_orchestration_step_becomes_thread_event(self):
        class Step:
            phase = "tool_execution"
            tool = "network_inspect"
            status = "completed"
            input_summary = "{}"
            output_summary = "No suspicious connections"
            duration_ms = 12.5

        bridge = NeMoAgentToolkitBridge([], ".")
        event = bridge.publish_orchestration_step(Step(), "inv-2")
        self.assertEqual(event.type, "nat_step_completed")
        self.assertEqual(event.data["tool"], "network_inspect")
        self.assertEqual(event.data["duration_ms"], 12.5)

    def test_network_request_uses_real_tool_path(self):
        self.assertEqual(IntentRouter().classify("Inspect active network connections").intent, IntentType.INVESTIGATION)
        orchestrator = ToolOrchestrator(use_mock_llm=True)
        orchestrator._select_tool = lambda *_: "network_inspect"
        with patch.object(orchestrator, "_execute_tool") as execute_tool:
            execute_tool.return_value = type("Call", (), {
                "tool": "network_inspect", "status": "completed", "result": {"output": "connections", "raw_output": "connections"},
                "error": None, "duration_ms": 1.0,
            })()
            with patch.object(orchestrator.llm, "chat", return_value="Network inspection completed."):
                result = orchestrator.handle_message("Inspect active network connections")
        self.assertTrue(result.success)
        self.assertEqual(result.tool_calls[0].tool, "network_inspect")

    def test_defender_targets_are_normalized_from_drive_requests(self):
        orchestrator = ToolOrchestrator(use_mock_llm=True)
        for request, expected in (("scan G; drive for viruses", "G:\\"), ("scan H:\\", "H:\\"), ("scan G drive", "G:\\")):
            self.assertEqual(orchestrator._build_tool_args("windows_defender_scan", request)["target"], expected)

    def test_model_json_and_workspace_read_tools(self):
        orchestrator = ToolOrchestrator(use_mock_llm=True)
        orchestrator.llm.chat = lambda *args, **kwargs: '```json\n{"tool":"workspace_read_file","arguments":{"filepath":"cyber_agent.py"},"reason":"Read the requested source file."}\n```'
        self.assertEqual(orchestrator._select_tool("Open cyber_agent.py", orchestrator.router.classify("analyze cyber_agent.py")), "workspace_read_file")
        self.assertEqual(orchestrator._build_tool_args("workspace_read_file", "Open cyber_agent.py")["filepath"], "cyber_agent.py")

    def test_investigation_save_preserves_state_when_windows_replace_is_locked(self):
        with tempfile.TemporaryDirectory() as directory:
            state_store = InvestigationState(directory)
            state = state_store.create("locked file test")
            with patch("cyber_os.investigation_state.os.replace", side_effect=OSError(5, "Access is denied")):
                state_store.save(state)
            self.assertTrue(Path(directory, f"{state['investigation_id']}.recovery.json").exists())

    def test_agent_loop_uses_tool_results_to_choose_next_step(self):
        orchestrator = ToolOrchestrator(use_mock_llm=True)
        responses = [
            {"tool": "workspace_scan", "arguments": {"workspace_path": ".", "max_files": 10}, "reason": "Start with a broad workspace scan to establish the current state."},
            {"tool": "secret_scan", "arguments": {"filepath": ".", "content": "AKIA1234567890ABCDEF"}, "reason": "The workspace scan suggests we need to inspect for exposed secrets."},
        ]

        def fake_chat_json(system, user, role="investigator"):
            return responses.pop(0) if responses else {"tool": "workspace_scan", "arguments": {"workspace_path": ".", "max_files": 10}, "reason": "Fallback to workspace scan."}

        orchestrator.llm.chat_json = fake_chat_json

        def fake_execute(tool_name, args):
            fake_result = {"success": True, "output": json.dumps({"findings": [{"severity": "high", "message": "Sample finding"}], "findings_count": 1}), "raw_output": "Sample findings", "findings": [{"severity": "high", "message": "Sample finding"}]}
            return type("ToolCall", (), {"tool": tool_name, "arguments": args, "status": "completed", "result": fake_result, "error": None, "duration_ms": 1.0})()

        orchestrator._execute_tool = fake_execute

        result = orchestrator.handle_message("Something feels wrong with my PC.")
        self.assertTrue(result.success)
        self.assertGreaterEqual(len(result.tool_calls), 2)
        self.assertEqual(result.tool_calls[0].tool, "workspace_scan")
        self.assertTrue(any(tc.tool == "secret_scan" for tc in result.tool_calls))

    def test_all_soc_agents_and_workflows_are_populated(self):
        from cyber_agent import BUILTIN_AGENTS, BUILTIN_WORKFLOWS, SOCOrchestrator

        agent = Mock()
        agent.execute_tool.return_value = {"success": True, "output": "test evidence"}
        orchestrator = SOCOrchestrator(use_mock=True, agent=agent)
        self.assertEqual(len(orchestrator.list_agents()), 13)
        for agent_id in BUILTIN_AGENTS:
            self.assertTrue(orchestrator._call_agent(agent_id, "read-only health check"))
        for workflow_name, workflow in BUILTIN_WORKFLOWS.items():
            result = orchestrator.run_workflow(workflow_name, "read-only workstation investigation")
            self.assertEqual(len(result["phases"]), len(workflow.phases))
            self.assertGreater(result["ledger"]["total_events"], 0)

    def test_builtin_workflow_compiler_does_not_return_empty_definition(self):
        from cyber_tools import ToolRegistry, AuditLogger, register_all_default_tools

        registry = ToolRegistry(AuditLogger())
        register_all_default_tools(registry)
        result = registry.tools["soc_compile_workflow"].python_func(workflow_name="incident-response")
        self.assertEqual(len(result["phases"]), 4)
        default_result = registry.tools["soc_compile_workflow"].python_func()
        self.assertEqual(len(default_result["phases"]), 4)
        validation = registry.tools["soc_validate_workflow"].python_func()
        self.assertTrue(validation["valid"])
        self.assertEqual(validation["workflow"], "incident-response")


    def test_end_to_end_investigation_loop_with_state_persistence(self):
        """Validate full agent loop: tool execution → finding accumulation → state persistence."""
        import tempfile
        import os
        from pathlib import Path
        
        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = ToolOrchestrator(workspace_path=tmpdir, use_mock_llm=True, max_tool_calls=3)
            
            # Mock tool responses with realistic findings
            tool_responses = [
                {"tool": "workspace_scan", "arguments": {"workspace_path": tmpdir, "max_files": 50}, "reason": "Initial broad scan"},
                {"tool": "secret_scan", "arguments": {"filepath": tmpdir}, "reason": "Found potential secrets"},
                {"tool": "static_analysis", "arguments": {"filepath": tmpdir}, "reason": "Further code analysis"},
            ]
            
            def mock_chat_json(system, user, role="investigator"):
                return tool_responses.pop(0) if tool_responses else {"tool": "workspace_scan", "arguments": {}, "reason": "Done"}
            
            def mock_execute_tool(tool_name, args):
                # Create realistic finding results based on tool type
                if tool_name == "workspace_scan":
                    tool_result = {
                        "findings": [{"severity": "medium", "message": "File found", "file": "test.txt"}],
                        "findings_count": 1,
                        "raw_output": "Workspace scan completed",
                        "success": True
                    }
                elif tool_name == "secret_scan":
                    tool_result = {
                        "findings": [{"type": "API Key", "line": 10}],
                        "findings_count": 1,
                        "raw_output": "Secret scan completed",
                        "success": True
                    }
                elif tool_name == "static_analysis":
                    tool_result = {
                        "findings": [{"severity": "high", "message": "Security issue", "type": "Hardcoded password"}],
                        "findings_count": 1,
                        "raw_output": "Analysis completed",
                        "success": True
                    }
                else:
                    tool_result = {"findings": [], "findings_count": 0, "raw_output": "", "success": True}
                
                return type("ToolCall", (), {
                    "tool": tool_name,
                    "arguments": args,
                    "status": "completed",
                    "result": tool_result,
                    "error": None,
                    "duration_ms": 10.0,
                })()
            
            orchestrator.llm.chat_json = mock_chat_json
            orchestrator._execute_tool = mock_execute_tool
            
            # Run the investigation
            result = orchestrator.handle_message("Investigate this workspace for security issues.")
            
            # Verify investigation executed
            self.assertTrue(result.success)
            self.assertGreater(len(result.tool_calls), 0)
            self.assertGreaterEqual(len(result.findings), 2, "Should have accumulated findings from multiple tools")
            
            # Verify investigation state was created and persisted
            self.assertIsNotNone(orchestrator.current_investigation)
            investigation_id = orchestrator.current_investigation["investigation_id"]
            
            # Verify the state file exists
            state_file = Path(tmpdir) / ".investigations" / f"{investigation_id}.json"
            self.assertTrue(state_file.exists(), f"Investigation state file should exist at {state_file}")
            
            # Load and verify the state
            loaded_state = orchestrator.investigation_state.load(investigation_id)
            self.assertIsNotNone(loaded_state)
            self.assertEqual(loaded_state["investigation_id"], investigation_id)
            self.assertEqual(loaded_state["status"], "completed")
            self.assertGreater(len(loaded_state["findings"]), 0, "Should have findings recorded in state")

if __name__ == "__main__":
    unittest.main()
