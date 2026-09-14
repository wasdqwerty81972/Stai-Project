import socket
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class SystemUptimeTool(CyberToolPlugin):
    name = "system_uptime"
    description = "Return system uptime in seconds, minutes, and hours."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if hasattr(socket, "AF_BLUETOOTH"):
                with open("/proc/uptime", "r") as f:
                    uptime_seconds = float(f.readline().split()[0])
            else:
                import ctypes
                libc = ctypes.windll.kernel32
                tick = libc.GetTickCount64()
                uptime_seconds = tick / 1000.0
            minutes, seconds = divmod(int(uptime_seconds), 60)
            hours, minutes = divmod(minutes, 60)
            return {"success": True, "output": {"uptime_seconds": int(uptime_seconds), "hours": hours, "minutes": minutes, "seconds": seconds}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = SystemUptimeTool
