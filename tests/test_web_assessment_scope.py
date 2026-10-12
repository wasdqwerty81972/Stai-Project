"""Regression tests for URL-scoped web assessments in the agent runtime."""

from __future__ import annotations

import json
import threading
import unittest
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest.mock import Mock, patch

from cyber_os.agent_runtime import AgentRuntime, _RunState
from cyber_os.doom_loop_detector import DoomLoopDetector
from cyber_os.stop_conditions import StopConditions


TARGET = "https://dvwa.example.test:4280/"


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name

    def to_manifest(self) -> Dict[str, Any]:
        return {"name": self.name, "description": f"test tool {self.name}"}


class _Agent:
    def __init__(self, tool_names: List[str]) -> None:
        self.registry = SimpleNamespace(tools={name: _Tool(name) for name in tool_names})
        self.workspace_path = "."
        self.cancel_event = threading.Event()
        self.calls: List[tuple[str, Dict[str, Any]]] = []
        self.results: Dict[str, Dict[str, Any]] = {}

    def execute_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append((name, dict(args)))
        return self.results.get(
            name,
            {"success": True, "output": f"{name} returned bounded test evidence " * 8},
        )


def _decision(tool: str, arguments: Optional[Dict[str, Any]] = None) -> str:
    return json.dumps({"action_type": "tool", "tool_name": tool, "arguments": arguments or {}})


def _final() -> str:
    return json.dumps({"action_type": "final_answer", "response": "Assessment summary"})


class WebAssessmentScopeTests(unittest.TestCase):
    def _runtime(self, names: Optional[List[str]] = None) -> tuple[AgentRuntime, _Agent]:
        if names is None:
            names = [
                "open_url", "web_security_headers", "web_tech_fingerprint",
                "xss_scanner", "sqli_scanner", "web_search", "network_inspect",
                "network_discover", "shell_exec",
            ]
        agent = _Agent(names)
        runtime = AgentRuntime(agent)
        runtime.max_steps = 12
        runtime._capture_browser_screenshot = lambda *args: None
        runtime._synthesize_final_report = lambda **kwargs: "Assessment summary"
        runtime._append_web_assessment_pdf_report = lambda _state, response: response
        return runtime, agent

    def _run_with_decisions(
        self,
        runtime: AgentRuntime,
        prompt: str,
        decisions: List[str],
        history: Optional[List[Dict[str, str]]] = None,
    ):
        pending = list(decisions)
        runtime._call_llm = lambda system, user: pending.pop(0) if pending else _final()
        return runtime.run_investigation(prompt, conversation_history=history)

    def test_explicit_assessment_forces_planned_scoped_checks_before_final(self) -> None:
        runtime, agent = self._runtime()

        self._run_with_decisions(
            runtime,
            f"Run a web security assessment for vulnerabilities at {TARGET}",
            [_final()] * 8,
        )

        called = [name for name, _ in agent.calls]
        self.assertEqual(
            called,
            ["open_url", "web_security_headers", "web_tech_fingerprint", "xss_scanner", "sqli_scanner"],
        )
        for name, args in agent.calls:
            if "url" in args:
                self.assertEqual(args["url"], TARGET, f"{name} must stay on the user-specified target")

    def test_model_local_tool_attempt_never_executes(self) -> None:
        runtime, agent = self._runtime()

        self._run_with_decisions(
            runtime,
            f"Run a web security assessment for vulnerabilities at {TARGET}",
            [_decision("network_inspect"), _final(), _final(), _final(), _final(), _final()],
        )

        self.assertNotIn("network_inspect", [name for name, _ in agent.calls])
        self.assertTrue(agent.calls, "a rejected local action should fall back to scoped web checks")

    def test_off_target_scanner_url_is_rejected_and_probe_uses_bound_target(self) -> None:
        runtime, agent = self._runtime()

        self._run_with_decisions(
            runtime,
            f"Run a web security assessment for vulnerabilities at {TARGET}",
            [_decision("xss_scanner", {"url": "https://attacker.example:9443/", "method": "POST"})]
            + [_final()] * 8,
        )

        xss_calls = [args for name, args in agent.calls if name == "xss_scanner"]
        self.assertEqual(len(xss_calls), 1)
        self.assertEqual(xss_calls[0]["url"], TARGET)
        self.assertEqual(xss_calls[0]["method"], "GET")
        self.assertNotEqual(xss_calls[0]["url"], "https://attacker.example:9443/")

    def test_recovery_cannot_switch_to_local_network_tool(self) -> None:
        runtime, agent = self._runtime()
        agent.results["open_url"] = {"success": False, "error": "fixture failure"}

        self._run_with_decisions(
            runtime,
            f"Run a web security assessment for vulnerabilities at {TARGET}",
            [
                _decision("open_url", {"url": TARGET}),
                _decision("network_inspect"),
            ] + [_final()] * 8,
        )

        self.assertNotIn("network_inspect", [name for name, _ in agent.calls])
        self.assertIn("web_security_headers", [name for name, _ in agent.calls])

    def test_pending_recovery_is_scope_checked_before_returning(self) -> None:
        runtime, agent = self._runtime()
        state = _RunState(
            investigation_id="inv_scope",
            session_id="scope-test",
            user_input=f"Run a web security assessment for vulnerabilities at {TARGET}",
            cancel_event=threading.Event(),
            stop_conditions=StopConditions(max_steps=5, max_elapsed_seconds=30),
            doom_loop_detector=DoomLoopDetector(),
            web_target_scope=AgentRuntime._derive_web_assessment_scope(
                f"Run a web security assessment for vulnerabilities at {TARGET}"
            ),
            pending_recovery={
                "action_type": "tool",
                "tool_name": "network_inspect",
                "arguments": {},
            },
        )

        decision = runtime._decide_next_step(state, "system", "", 1)
        enforced = runtime._enforce_web_assessment_decision(state, decision)

        self.assertEqual(enforced["action_type"], "tool")
        self.assertNotEqual(enforced["tool_name"], "network_inspect")
        self.assertEqual(enforced["tool_name"], "open_url")

    def test_prior_local_network_history_does_not_change_current_url_scope(self) -> None:
        runtime, agent = self._runtime()

        self._run_with_decisions(
            runtime,
            f"Assess web security at {TARGET}",
            [_decision("network_discover"), _final()] + [_final()] * 8,
            history=[{"role": "user", "content": "Scan my local subnet for devices"}],
        )

        self.assertNotIn("network_discover", [name for name, _ in agent.calls])
        self.assertIn("web_security_headers", [name for name, _ in agent.calls])

    def test_assessment_detection_uses_current_request_and_requires_action(self) -> None:
        self.assertIsNotNone(AgentRuntime._derive_web_assessment_scope(TARGET))
        self.assertTrue(AgentRuntime._is_web_assessment_request(TARGET))
        self.assertIsNone(AgentRuntime._derive_web_assessment_scope(f"What is this URL? {TARGET}"))
        self.assertFalse(AgentRuntime._is_web_assessment_request(f"What is this URL? {TARGET}"))
        scope = AgentRuntime._derive_web_assessment_scope(
            f"Test the security of this web application: {TARGET}"
        )
        self.assertIsNotNone(scope)
        self.assertEqual(scope.target_url, TARGET)

    def test_target_scope_includes_scheme_as_well_as_host_and_port(self) -> None:
        scope = AgentRuntime._derive_web_assessment_scope(TARGET)

        self.assertEqual(scope.scheme, "https")
        self.assertTrue(AgentRuntime._url_matches_web_scope(TARGET, scope))
        self.assertFalse(
            AgentRuntime._url_matches_web_scope("http://dvwa.example.test:4280/", scope)
        )
        self.assertFalse(
            AgentRuntime._url_matches_web_scope("https://dvwa.example.test.:4280/", scope)
        )

    def test_backslash_authority_is_rejected_before_runtime_routing(self) -> None:
        import requests
        from urllib.parse import urlsplit

        from cyber_agent import CyberAgent

        malformed = r"http://trusted.test\evil.test:9000/"
        prepared_url = requests.Request("GET", malformed).prepare().url
        self.assertEqual(urlsplit(prepared_url).hostname, "trusted.test")

        agent = CyberAgent.__new__(CyberAgent)
        agent.registry = SimpleNamespace(tools={"open_url": _Tool("open_url")})
        routed: List[str] = []
        agent._run_ai_orchestrated_request = (
            lambda prompt, **kwargs: routed.append(prompt) or "runtime"
        )
        agent.orchestrator = SimpleNamespace(
            _call_role=lambda *args, **kwargs: "legacy fallback"
        )

        response = agent._process_chat_command(malformed)

        self.assertIn("No request was sent", response)
        self.assertEqual(routed, [])
        self.assertIsNone(AgentRuntime._derive_web_assessment_scope(malformed))

    def test_target_scope_canonicalizes_the_authority_for_http_clients(self) -> None:
        import requests
        from urllib.parse import urlsplit

        target = "HTTPS://BÜCHER.Example:443/app?q=1#section"
        scope = AgentRuntime._derive_web_assessment_scope(target)

        self.assertIsNotNone(scope)
        self.assertEqual(scope.host, "xn--bcher-kva.example")
        self.assertEqual(scope.scheme, "https")
        self.assertEqual(scope.port, 443)
        self.assertEqual(scope.target_url, "https://xn--bcher-kva.example/app?q=1")

        prepared = urlsplit(requests.Request("GET", scope.target_url).prepare().url)
        self.assertEqual(prepared.scheme, scope.scheme)
        self.assertEqual(prepared.hostname, scope.host)
        self.assertEqual(prepared.port or 443, scope.port)

        ipv6_scope = AgentRuntime._derive_web_assessment_scope("http://[2001:0db8::1]:80/status")
        self.assertIsNotNone(ipv6_scope)
        self.assertEqual(ipv6_scope.host, "2001:db8::1")
        self.assertEqual(ipv6_scope.target_url, "http://[2001:db8::1]/status")

        for ambiguous in (
            "http://127.1/",
            "http://0x7f000001/",
            "http://trusted%2eexample/",
            "http://trusted.example:/",
        ):
            with self.subTest(url=ambiguous):
                self.assertIsNone(AgentRuntime._derive_web_assessment_scope(ambiguous))

    def test_missing_assessment_tools_produce_no_request_report(self) -> None:
        runtime, agent = self._runtime([])

        result = self._run_with_decisions(runtime, TARGET, [_final()])

        self.assertEqual(agent.calls, [])
        self.assertIn("No request was sent", result.response)
        self.assertIn("Unavailable checks", result.response)
        self.assertNotIn("Assessment summary", result.response)

    def test_plain_local_subnet_scan_keeps_network_discovery_heuristic(self) -> None:
        runtime, _agent = self._runtime(["network_discover", "network_inspect"])
        state = _RunState(
            investigation_id="inv_local",
            session_id="local-test",
            user_input="Scan my local subnet for devices",
            cancel_event=threading.Event(),
            stop_conditions=StopConditions(max_steps=5, max_elapsed_seconds=30),
            doom_loop_detector=DoomLoopDetector(),
        )

        decision = runtime._heuristic_decide_action(state, "", 1)

        self.assertEqual(decision["tool_name"], "network_discover")

    def test_explicit_assessment_and_standalone_url_route_to_tool_runtime(self) -> None:
        from cyber_agent import CyberAgent

        agent = CyberAgent.__new__(CyberAgent)
        agent.registry = SimpleNamespace(tools={"open_url": _Tool("open_url")})
        routed: List[str] = []
        agent._run_ai_orchestrated_request = lambda prompt, **kwargs: routed.append(prompt) or "runtime"
        agent.orchestrator = SimpleNamespace(
            _call_role=lambda *args, **kwargs: "legacy fallback"
        )

        response = agent._process_chat_command(f"Assess the security of {TARGET}")
        standalone_response = agent._process_chat_command(TARGET)
        rejected_response = agent._process_chat_command("https://dvwa.example.test.:4280/")

        self.assertEqual(response, "runtime")
        self.assertEqual(standalone_response, "runtime")
        self.assertIn("No request was sent", rejected_response)
        self.assertEqual(routed, [f"Assess the security of {TARGET}", TARGET])

    def test_negated_local_scan_with_web_assessment_routes_only_to_web_runtime(self) -> None:
        from cyber_agent import CyberAgent

        prompt = "Don't scan my network; assess https://target.example"
        agent = CyberAgent.__new__(CyberAgent)
        agent.registry = SimpleNamespace(tools={
            "open_url": _Tool("open_url"),
            "network_discover": _Tool("network_discover"),
        })
        routed: List[str] = []
        agent._run_ai_orchestrated_request = (
            lambda text, **kwargs: routed.append(text) or "web assessment runtime"
        )
        agent.execute_tool = Mock(return_value={
            "success": True,
            "output": json.dumps({"success": True, "hosts": []}),
        })

        response = agent._process_chat_command(prompt)

        self.assertEqual(response, "web assessment runtime")
        self.assertEqual(routed, [prompt])
        agent.execute_tool.assert_not_called()

    def test_positive_local_network_scan_still_runs_network_discovery(self) -> None:
        from cyber_agent import CyberAgent

        agent = CyberAgent.__new__(CyberAgent)
        agent.registry = SimpleNamespace(tools={"network_discover": _Tool("network_discover")})
        agent._publish_ui_event = Mock()
        agent.execute_tool = Mock(return_value={
            "success": True,
            "output": json.dumps({
                "success": True,
                "network": "192.0.2.0/24",
                "addresses_observed": 0,
                "hosts_checked": 256,
                "icmp_responders": 0,
                "hosts": [],
            }),
        })
        agent._run_ai_orchestrated_request = Mock(return_value="web runtime")

        response = agent._process_chat_command("Scan my local subnet for devices")

        self.assertIn("192.0.2.0/24", response)
        agent.execute_tool.assert_called_once_with("network_discover", {})
        agent._run_ai_orchestrated_request.assert_not_called()

    def test_subagent_decision_is_replaced_by_a_scoped_tool(self) -> None:
        runtime, agent = self._runtime()
        state = _RunState(
            investigation_id="inv_subagent",
            session_id="scope-test",
            user_input=f"Run a web security assessment for vulnerabilities at {TARGET}",
            cancel_event=threading.Event(),
            stop_conditions=StopConditions(max_steps=5, max_elapsed_seconds=30),
            doom_loop_detector=DoomLoopDetector(),
            web_target_scope=AgentRuntime._derive_web_assessment_scope(
                f"Run a web security assessment for vulnerabilities at {TARGET}"
            ),
        )

        enforced = runtime._enforce_web_assessment_decision(
            state,
            {"action_type": "subagent", "profile": "vulnerability_analysis", "objective": "scan"},
        )

        self.assertEqual(enforced["action_type"], "tool")
        self.assertEqual(enforced["tool_name"], "open_url")
        self.assertNotIn("subagent", [name for name, _ in agent.calls])

    def test_subagent_attempt_during_full_run_never_delegates(self) -> None:
        runtime, agent = self._runtime()

        self._run_with_decisions(
            runtime,
            TARGET,
            [json.dumps({"action_type": "subagent", "profile": "threat_analysis"})]
            + [_final()] * 8,
        )

        self.assertEqual(
            [name for name, _ in agent.calls],
            ["open_url", "web_security_headers", "web_tech_fingerprint", "xss_scanner", "sqli_scanner"],
        )

    def test_model_cannot_claim_confirmed_xss_or_sqli_from_negative_probe_evidence(self) -> None:
        runtime, agent = self._runtime()
        agent.results["xss_scanner"] = {
            "success": True,
            "output": {
                "reflected": False,
                "status": 200,
                "note": "The harmless test marker was not reflected in the response body.",
            },
        }
        agent.results["sqli_scanner"] = {
            "success": True,
            "output": {
                "possible_sqli": False,
                "response_length_delta": 2,
                "evidence": "Boolean probe responses were similar in length.",
            },
        }
        malicious_final = json.dumps({
            "action_type": "final_answer",
            "response": (
                "Confirmed exploitable XSS and SQL injection vulnerabilities were found. "
                "A confirmed CSRF vulnerability was also found. The site is vulnerable."
            ),
        })

        result = self._run_with_decisions(runtime, TARGET, [malicious_final] * 8)

        self.assertNotIn("Confirmed exploitable XSS", result.response)
        self.assertNotIn("SQL injection vulnerabilities were found", result.response)
        self.assertNotIn("confirmed CSRF vulnerability", result.response)
        self.assertNotIn("The site is vulnerable", result.response)
        self.assertIn("does not prove executable XSS", result.response)
        self.assertIn("SQL injection probe did not flag", result.response)
        self.assertIn("No CSRF-specific check was available", result.response)

    def test_scanner_report_reads_real_serialized_plugin_envelopes(self) -> None:
        runtime, agent = self._runtime()
        agent.results["xss_scanner"] = {
            "success": True,
            "output": json.dumps({
                "success": True,
                "output": {"reflected": False, "status": 200},
                "error": "",
            }),
        }
        agent.results["sqli_scanner"] = {
            "success": True,
            "output": json.dumps({
                "success": True,
                "output": {"possible_sqli": False, "response_length_delta": 2},
                "error": "",
            }),
        }

        result = self._run_with_decisions(runtime, TARGET, [_final()] * 8)

        self.assertIn("harmless XSS marker was not reflected", result.response)
        self.assertIn("SQL injection probe did not flag", result.response)

    def test_final_report_cannot_hide_failed_tools_with_fabricated_success_claim(self) -> None:
        runtime, agent = self._runtime()
        agent.results["open_url"] = {"success": False, "error": "browser failed"}
        agent.results["web_security_headers"] = {
            "success": False,
            "error": "request failed",
        }
        fabricated_final = json.dumps({
            "action_type": "final_answer",
            "response": "open_url and web_security_headers completed successfully.",
        })

        result = self._run_with_decisions(runtime, TARGET, [fabricated_final] * 8)

        self.assertNotIn("completed successfully", result.response)
        self.assertIn("`open_url`: failed", result.response)
        self.assertIn("`web_security_headers`: failed", result.response)
        self.assertIn("`web_tech_fingerprint`: completed", result.response)

    def test_browser_route_guard_blocks_cross_scheme_and_off_origin_requests(self) -> None:
        runtime, agent = self._runtime()
        scope = AgentRuntime._derive_web_assessment_scope(TARGET)

        class _Route:
            def __init__(self, url: str) -> None:
                self.request = SimpleNamespace(url=url)
                self.continued = False
                self.aborted = False

            def continue_(self) -> None:
                self.continued = True

            def abort(self) -> None:
                self.aborted = True

        class _Context:
            def __init__(self) -> None:
                self.handler = None
                self.routes: List[_Route] = []

            def route(self, _pattern: str, handler: Any) -> None:
                self.handler = handler

            def unroute(self, _pattern: str, handler: Any) -> None:
                self.assert_same_handler(handler)
                self.handler = None

            def assert_same_handler(self, handler: Any) -> None:
                if handler is not self.handler:
                    raise AssertionError("route handler mismatch")

        context = _Context()
        same_origin = _Route(TARGET)
        cross_scheme = _Route("http://dvwa.example.test:4280/resource")
        off_origin = _Route("https://outside.example.test:4280/resource")
        agent.execute_tool = lambda name, args: (
            context.handler(same_origin),
            context.handler(cross_scheme),
            context.handler(off_origin),
            {"success": True, "output": "visited"},
        )[-1]
        with patch("Tools_cyber.browser_manager.BrowserManager.get_instance") as get_instance:
            get_instance.return_value = SimpleNamespace(context=context)
            result = runtime._execute_scoped_tool(
                _RunState(
                    investigation_id="route_scope",
                    session_id="scope-test",
                    user_input=TARGET,
                    cancel_event=threading.Event(),
                    stop_conditions=StopConditions(max_steps=5, max_elapsed_seconds=30),
                    doom_loop_detector=DoomLoopDetector(),
                    web_target_scope=scope,
                ),
                "open_url",
                {"url": TARGET},
            )

        self.assertTrue(result["success"])
        self.assertTrue(same_origin.continued)
        self.assertTrue(cross_scheme.aborted)
        self.assertTrue(off_origin.aborted)

    def test_scoped_model_prompt_contains_only_registered_assessment_tools(self) -> None:
        runtime, _agent = self._runtime()
        captured: List[tuple[str, str]] = []

        def capture(*, system: str, user: str) -> str:
            system_prompt, user_prompt = system, user
            captured.append((system_prompt, user_prompt))
            return _final()

        runtime._call_llm = capture
        runtime.run_investigation(TARGET)

        self.assertTrue(captured)
        system_prompt, user_prompt = captured[0]
        tool_block = system_prompt.split("<available_tools>", 1)[1].split("</available_tools>", 1)[0]
        listed_names = {f'"name": "{name}"' for name in (
            "open_url", "web_security_headers", "web_tech_fingerprint", "xss_scanner", "sqli_scanner"
        )}
        self.assertTrue(all(name in tool_block for name in listed_names))
        self.assertNotIn('"name": "network_inspect"', tool_block)
        self.assertNotIn('"name": "shell_exec"', tool_block)
        self.assertNotIn("\"network_inspect\"", user_prompt)
        self.assertNotIn("<subagent_guidance>", system_prompt)

    def test_standalone_url_runs_scoped_checks(self) -> None:
        runtime, agent = self._runtime()

        self._run_with_decisions(runtime, TARGET, [_final()] * 8)

        self.assertEqual(
            [name for name, _ in agent.calls],
            ["open_url", "web_security_headers", "web_tech_fingerprint", "xss_scanner", "sqli_scanner"],
        )

    def test_url_only_chat_assessment_returns_a_downloadable_pdf_link(self) -> None:
        import os
        from unittest.mock import Mock

        runtime, agent = self._runtime()
        report_id = "0123456789abcdef0123456789abcdef"
        writer = Mock(return_value={
            "success": True,
            "report_id": report_id,
            "path": f"output/reports/web_assessments/{report_id}.pdf",
        })
        runtime._append_web_assessment_pdf_report = (
            AgentRuntime._append_web_assessment_pdf_report.__get__(runtime, AgentRuntime)
        )
        fabricated_final = json.dumps({
            "action_type": "final_answer",
            "response": "The scoped checks finished.",
        })
        decisions = [fabricated_final] * 8
        runtime._call_llm = lambda _system, _user: decisions.pop(0) if decisions else _final()

        from cyber_agent import CyberAgent
        chat_agent = CyberAgent.__new__(CyberAgent)
        chat_agent.agent_runtime = runtime
        chat_agent.current_investigation = None
        chat_agent.registry = agent.registry

        with patch("cyber_os.web_assessment_report.write_web_assessment_pdf", writer), patch.dict(
            os.environ, {"NEXT_PUBLIC_BACKEND_ORIGIN": "http://localhost:6764"}
        ):
            response = chat_agent._process_chat_command(TARGET)

        self.assertEqual(
            [name for name, _ in agent.calls],
            ["open_url", "web_security_headers", "web_tech_fingerprint", "xss_scanner", "sqli_scanner"],
        )
        self.assertIn(
            f"[Download detailed PDF report](http://127.0.0.1:6764/api/reports/web-assessments/{report_id}.pdf)",
            response,
        )
        writer.assert_called_once()
        self.assertEqual(writer.call_args.args[0], AgentRuntime._derive_web_assessment_scope(TARGET).target_url)

    def test_pdf_generation_failure_does_not_return_a_dead_download_link(self) -> None:
        import os
        from unittest.mock import Mock

        runtime, _agent = self._runtime()
        runtime._append_web_assessment_pdf_report = (
            AgentRuntime._append_web_assessment_pdf_report.__get__(runtime, AgentRuntime)
        )
        final = json.dumps({"action_type": "final_answer", "response": "Assessment summary"})

        with patch(
            "cyber_os.web_assessment_report.write_web_assessment_pdf",
            Mock(side_effect=RuntimeError("PDF backend unavailable")),
        ), patch.dict(os.environ, {"NEXT_PUBLIC_BACKEND_ORIGIN": "http://localhost:6764"}):
            result = self._run_with_decisions(runtime, TARGET, [final] * 8)

        self.assertNotIn("[Download detailed PDF report]", result.response)
        self.assertIn("PDF report could not be generated", result.response)

    def test_xss_probe_uses_only_a_benign_get_and_does_not_follow_redirects(self) -> None:
        from Tools_cyber.xss_scanner import XssScannerTool

        response = SimpleNamespace(text="SVS_XSS_REFLECTION_PROBE", status_code=200)
        with patch("requests.get", return_value=response) as get, patch("requests.post") as post:
            result = XssScannerTool().run({
                "url": TARGET,
                "method": "POST",
                "payload": "<script>alert(1)</script>",
            })

        self.assertTrue(result["success"])
        self.assertEqual(get.call_count, 1)
        self.assertEqual(get.call_args.kwargs["allow_redirects"], False)
        self.assertEqual(get.call_args.kwargs["params"]["q"], "SVS_XSS_REFLECTION_PROBE")
        post.assert_not_called()

    def test_sqli_probe_uses_get_only_and_does_not_follow_redirects(self) -> None:
        from Tools_cyber.sqli_scanner import SqliScannerTool

        response = SimpleNamespace(text="fixture response", status_code=200)
        with patch("requests.get", return_value=response) as get, patch("requests.post") as post:
            result = SqliScannerTool().run({"url": TARGET})

        self.assertTrue(result["success"])
        self.assertEqual(get.call_count, 2)
        self.assertTrue(all(call.kwargs["allow_redirects"] is False for call in get.call_args_list))
        post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
