from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class CertFingerprintTool(CyberToolPlugin):
    name = "cert_fingerprint"
    description = "Get SHA-256 fingerprint from a TLS certificate."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import hashlib
        import ssl
        import socket
        host = arguments.get("host", "")
        port = int(arguments.get("port", 443))
        if not host:
            return {"success": False, "output": {}, "error": "Missing 'host' argument."}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as conn:
                with ctx.wrap_socket(conn, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
            fingerprint = hashlib.sha256(cert).hexdigest()
            return {"success": True, "output": {"host": host, "port": port, "sha256_fingerprint": fingerprint}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = CertFingerprintTool
