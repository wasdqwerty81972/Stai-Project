import socket
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class PortScanTool(CyberToolPlugin):
    name = "port_scan"
    description = "Test connectivity to a specific TCP port on a host."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        host = arguments.get("ip") or arguments.get("host", "")
        port = arguments.get("port", 80)
        if not host:
            return {"success": False, "output": {}, "error": "Missing 'ip' or 'host' argument."}
        try:
            port = int(port)
        except (TypeError, ValueError):
            return {"success": False, "output": {}, "error": "Port must be an integer."}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            result = sock.connect_ex((host, port))
            sock.close()
            return {"success": True, "output": {"open": result == 0, "port": port, "host": host}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = PortScanTool
