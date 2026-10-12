"""Registered WebRecon callables must report HTTP failures explicitly."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

import cyber_tools
from cyber_tools import AuditLogger, ToolRegistry, register_all_default_tools


class WebReconFailureResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._temp_dir.cleanup)
        registry = ToolRegistry(
            AuditLogger(log_path=str(Path(cls._temp_dir.name) / "audit.jsonl"))
        )
        register_all_default_tools(registry)
        cls.callables = {
            name: registry.tools[name].python_func
            for name in (
                "web_security_headers",
                "web_robots_txt",
                "web_tech_fingerprint",
                "web_sensitive_paths",
            )
        }

    def test_registered_web_recon_callables_report_request_errors(self) -> None:
        error = requests.ConnectionError("network unavailable")
        cases = {
            "web_security_headers": {},
            "web_robots_txt": {},
            "web_tech_fingerprint": {},
            "web_sensitive_paths": {"paths": ["/health"]},
        }

        for name, extra_args in cases.items():
            with self.subTest(tool=name), patch.object(
                cyber_tools.requests, "get", side_effect=error
            ):
                result = self.callables[name](url="https://example.test", **extra_args)

                self.assertIs(result["success"], False)
                if name == "web_sensitive_paths":
                    self.assertIn("network unavailable", result["errors"][0]["error"])
                else:
                    self.assertIn("network unavailable", result["error"])

    def test_registered_web_recon_requests_do_not_follow_redirects(self) -> None:
        response = type(
            "Response",
            (),
            {"status_code": 404, "headers": {}, "text": "", "url": "https://example.test/"},
        )()
        cases = {
            "web_security_headers": {},
            "web_robots_txt": {},
            "web_tech_fingerprint": {},
            "web_sensitive_paths": {"paths": ["/health"]},
        }

        for name, extra_args in cases.items():
            with self.subTest(tool=name), patch.object(
                cyber_tools.requests, "get", return_value=response
            ) as get:
                self.callables[name](url="https://example.test", **extra_args)

                self.assertTrue(get.call_args_list)
                self.assertTrue(
                    all(call.kwargs.get("allow_redirects") is False for call in get.call_args_list)
                )
                if name in {"web_security_headers", "web_tech_fingerprint"}:
                    self.assertTrue(
                        all(call.kwargs.get("verify") is True for call in get.call_args_list)
                    )


if __name__ == "__main__":
    unittest.main()
