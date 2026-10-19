import socket
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class DnsLookupTool(CyberToolPlugin):
    name = "dns_lookup"
    description = "Resolve A, AAAA, MX, and TXT records for a domain."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import dns.resolver
        domain = arguments.get("domain", "")
        record_type = arguments.get("type", "A").upper()
        if not domain:
            return {"success": False, "output": {}, "error": "Missing 'domain' argument."}
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=5)
            records = [str(r) for r in answers]
            return {"success": True, "output": {"domain": domain, "type": record_type, "records": records}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = DnsLookupTool
