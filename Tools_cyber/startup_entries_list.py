from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class StartupEntriesListTool(CyberToolPlugin):
    name = "startup_entries_list"
    description = "Enumerate autorun/startup entries on the host."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import subprocess
        if __import__("sys").platform == "win32":
            cmd = "powershell -NoProfile -Command \"Get-CimInstance Win32_StartupCommand | Select Name,Command,Location\""
        else:
            cmd = "ls ~/.config/autostart 2>/dev/null || echo 'no autostart dir'"
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            return {"success": True, "output": {"stdout": res.stdout, "stderr": res.stderr, "returncode": res.returncode}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = StartupEntriesListTool
