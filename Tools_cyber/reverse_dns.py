from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class ReverseDnsTool(CyberToolPlugin):
    name = "reverse_dns"
    description = "Perform reverse DNS lookup for an IP address."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import dns.reversename
        import dns.resolver
        ip = arguments.get("ip", "")
        if not ip:
            return {"success": False, "output": {}, "error": "Missing 'ip' argument."}
        try:
            rev = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev, 'PTR', lifetime=5)
            hostnames = [str(r).rstrip('.') for r in answers]
            return {"success": True, "output": {"ip": ip, "hostnames": hostnames}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = ReverseDnsTool
