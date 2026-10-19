"""Regression tests for the registered web security headers tool."""

from __future__ import annotations

import json
import unittest
from unittest.mock import Mock, patch

import requests

from cyber_agent import CyberAgent


class WebSecurityHeadersToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = CyberAgent(workspace_path=".")
        self.agent._wait_for_approval = lambda *args, **kwargs: True

    def test_registered_tool_fetches_and_parses_security_headers(self) -> None:
        response = Mock(
            status_code=200,
            url="https://example.test/",
            headers={
                "Server": "fixture-server",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Content-Type-Options": "nosniff",
            },
        )

        with patch("requests.get", return_value=response) as get:
            result = self.agent.execute_tool(
                "web_security_headers", {"url": "https://example.test"}
            )

        self.assertTrue(result["success"], result["error"])
        output = json.loads(result["output"])
        self.assertIn("status_code", output)
        self.assertEqual(output["status_code"], 200)
        self.assertEqual(output["tls_verification"], "verified")
        self.assertIs(get.call_args.kwargs.get("verify"), True)
        self.assertEqual(output["server"], "fixture-server")
        self.assertEqual(
            output["security_headers"]["Strict-Transport-Security"],
            "max-age=31536000",
        )
        self.assertEqual(
            output["missing_security_headers"],
            [
                "Content-Security-Policy",
                "X-Frame-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            ],
        )

    def test_request_exception_is_reported_as_tool_failure(self) -> None:
        with patch("requests.get", side_effect=requests.ConnectionError("offline")):
            result = self.agent.execute_tool(
                "web_security_headers", {"url": "https://example.test"}
            )

        self.assertFalse(result["success"])
        self.assertIn("offline", result["error"])


if __name__ == "__main__":
    unittest.main()
