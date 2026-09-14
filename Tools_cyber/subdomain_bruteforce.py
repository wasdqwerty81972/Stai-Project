from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class SubdomainBruteforceTool(CyberToolPlugin):
    name = "subdomain_bruteforce"
    description = "Resolve a small wordlist of common subdomains for a given domain."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import dns.resolver
        domain = arguments.get("domain", "")
        wordlist = arguments.get("wordlist", ["www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "portal", "vpn", "cloud", "git", "jira", "wiki", "blog", "shop", "support", "cdn", "static", "app"])
        if not domain:
            return {"success": False, "output": {}, "error": "Missing 'domain' argument."}
        found = []
        for sub in wordlist:
            fqdn = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(fqdn, 'A', lifetime=3)
                ips = [str(r) for r in answers]
                found.append({"subdomain": fqdn, "ip": ips[0], "all_ips": ips})
            except Exception:
                pass
        return {"success": True, "output": {"domain": domain, "subdomains_found": len(found), "subdomains": found}, "error": ""}


TOOL_CLASS = SubdomainBruteforceTool
