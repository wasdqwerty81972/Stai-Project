import hashlib
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class SslCertInfoTool(CyberToolPlugin):
    name = "ssl_cert_info"
    description = "Fetch SSL certificate information for a hostname."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        hostname = arguments.get("url", "") or arguments.get("host", "")
        if not hostname:
            return {"success": False, "output": {}, "error": "Missing 'url' or 'host' argument."}
        hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]
        try:
            import ssl
            import socket as sock
            ctx = ssl.create_default_context()
            with sock.create_connection((hostname, 443), timeout=10) as conn:
                with ctx.wrap_socket(conn, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            return {"success": True, "output": {"host": hostname, "cert": cert}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = SslCertInfoTool
