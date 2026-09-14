import re
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class RobotsParserTool(CyberToolPlugin):
    name = "robots_parser"
    description = "Fetch and parse robots.txt directives and sitemaps."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        from urllib.parse import urlparse
        url = arguments.get("url", "")
        timeout = int(arguments.get("timeout", 10))
        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument."}
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            resp = requests.get(robots_url, timeout=timeout)
            if resp.status_code == 200:
                disallow = re.findall(r"Disallow:\s*(.+)", resp.text, re.IGNORECASE)
                allow = re.findall(r"Allow:\s*(.+)", resp.text, re.IGNORECASE)
                sitemaps = re.findall(r"Sitemap:\s*(.+)", resp.text, re.IGNORECASE)
                return {
                    "success": True,
                    "output": {
                        "url": robots_url,
                        "found": True,
                        "disallow_paths": [d.strip() for d in disallow],
                        "allow_paths": [a.strip() for a in allow],
                        "sitemaps": [s.strip() for s in sitemaps],
                    },
                    "error": "",
                }
            return {"success": True, "output": {"url": robots_url, "found": False, "status": resp.status_code}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = RobotsParserTool
