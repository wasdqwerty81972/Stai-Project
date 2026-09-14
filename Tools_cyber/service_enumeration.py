from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class ServiceEnumerationTool(CyberToolPlugin):
    name = "service_enumeration"
    description = "List running services from common local sources."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import subprocess
        if __import__("sys").platform == "win32":
            cmd = "powershell -NoProfile -Command \"Get-Service | Select-Object Name,Status,DisplayName\""
        else:
            cmd = "systemctl list-units --type=service --no-pager --all || service --status-all"
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            return {"success": True, "output": {"stdout": res.stdout, "stderr": res.stderr, "returncode": res.returncode}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = ServiceEnumerationTool
