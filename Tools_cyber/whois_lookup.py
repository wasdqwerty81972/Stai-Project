import socket
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class WhoisLookupTool(CyberToolPlugin):
    name = "whois_lookup"
    description = "Perform a WHOIS lookup for a domain."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        domain = arguments.get("domain", "")
        if not domain:
            return {"success": False, "output": {}, "error": "Missing 'domain' argument."}
        try:
            import whois
        except Exception:
            return {"success": False, "output": {}, "error": "python-whois is not installed."}
        try:
            data = whois.whois(domain)
            return {"success": True, "output": {"domain": domain, "whois": str(data)}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = WhoisLookupTool
