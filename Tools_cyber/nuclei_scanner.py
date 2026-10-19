from typing import Any, Dict, List
from cyber_tools import CyberToolPlugin, RiskLevel
import json
import subprocess
import tempfile
import os


class NucleiScannerTool(CyberToolPlugin):
    """Nuclei template-based vulnerability scanner - READ_ONLY scanning mode."""
    name = "nuclei_scan"
    description = "Run Nuclei vulnerability templates against target (read-only, no exploitation)"
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        target = arguments.get("target", "")
        templates = arguments.get("templates", [])  # e.g., ["cves/", "vulnerabilities/", "exposures/"]
        severity = arguments.get("severity", "")  # critical,high,medium,low,info
        tags = arguments.get("tags", [])  # e.g., ["sqli", "xss", "rce", "graphql"]
        rate_limit = arguments.get("rate_limit", 150)
        timeout = arguments.get("timeout", 30)
        retries = arguments.get("retries", 1)
        silent = arguments.get("silent", True)
        json_output = arguments.get("json_output", True)

        if not target:
            return {"success": False, "output": {}, "error": "Missing 'target' argument."}

        # Check if nuclei is available
        nuclei_path = self._find_nuclei()
        if not nuclei_path:
            return {"success": False, "output": {}, "error": "Nuclei not found. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}

        try:
            cmd = [nuclei_path, "-target", target]

            if templates:
                for t in templates:
                    cmd.extend(["-t", t])
            if severity:
                cmd.extend(["-severity", severity])
            if tags:
                for tag in tags:
                    cmd.extend(["-tags", tag])
            cmd.extend(["-rate-limit", str(rate_limit)])
            cmd.extend(["-timeout", str(timeout)])
            cmd.extend(["-retries", str(retries)])
            if silent:
                cmd.append("-silent")
            if json_output:
                cmd.append("-json")

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            findings = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass

            return {
                "success": True,
                "output": {
                    "target": target,
                    "templates_used": templates or "default",
                    "severity_filter": severity or "all",
                    "tags_filter": tags or "all",
                    "findings_count": len(findings),
                    "findings": findings,
                    "stderr": result.stderr if result.stderr else None
                },
                "error": result.stderr if result.returncode != 0 and not findings else ""
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "output": {}, "error": "Nuclei scan timed out (5 min)"}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}

    def _find_nuclei(self) -> str:
        """Find nuclei binary in PATH or common locations."""
        import shutil
        # Check PATH
        path = shutil.which("nuclei")
        if path:
            return path
        # Check common Go bin locations
        for base in [os.path.expanduser("~/go/bin"), "/usr/local/go/bin", "/opt/homebrew/bin"]:
            candidate = os.path.join(base, "nuclei")
            if os.path.exists(candidate):
                return candidate
        # Check Windows
        if os.name == "nt":
            for base in [os.path.expanduser("~/go/bin"), "C:/Go/bin"]:
                candidate = os.path.join(base, "nuclei.exe")
                if os.path.exists(candidate):
                    return candidate
        return ""


TOOL_CLASS = NucleiScannerTool