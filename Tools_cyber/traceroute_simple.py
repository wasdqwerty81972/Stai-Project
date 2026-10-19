from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class TracerouteSimpleTool(CyberToolPlugin):
    name = "traceroute_simple"
    description = "Platform-aware traceroute wrapper."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import subprocess
        target = arguments.get("target", "")
        if not target:
            return {"success": False, "output": {}, "error": "Missing 'target' argument."}
        cmd = f"tracert {target}" if __import__("sys").platform == "win32" else f"traceroute -m 30 {target}"
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return {"success": True, "output": {"target": target, "stdout": res.stdout, "stderr": res.stderr, "returncode": res.returncode}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = TracerouteSimpleTool
