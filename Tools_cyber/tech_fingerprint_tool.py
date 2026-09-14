from typing import Any, Dict, List
from cyber_tools import CyberToolPlugin, RiskLevel


class TechFingerprintTool(CyberToolPlugin):
    name = "tech_fingerprint"
    description = "Detect technologies, CMS, and frameworks from HTTP headers and response body."
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        url = arguments.get("url", "")
        timeout = int(arguments.get("timeout", 10))
        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument."}
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            text_sample = resp.text.lower()
            tech: List[Dict[str, str]] = []
            if "x-powered-by" in headers:
                tech.append({"name": headers["x-powered-by"], "category": "backend"})
            if "server" in headers:
                tech.append({"name": headers["server"], "category": "server"})
            if "x-drupal-cache" in headers or "drupal" in text_sample[:1000]:
                tech.append({"name": "Drupal", "category": "cms"})
            if "x-generator" in headers and "wordpress" in headers["x-generator"].lower():
                tech.append({"name": "WordPress", "category": "cms"})
            if "wp-content" in resp.text:
                tech.append({"name": "WordPress", "category": "cms"})
            if "react" in text_sample[:5000] or "next.js" in text_sample[:5000]:
                tech.append({"name": "React/Next.js", "category": "frontend"})
            if "joomla" in text_sample:
                tech.append({"name": "Joomla", "category": "cms"})
            return {"success": True, "output": {"url": url, "technologies": tech, "detected": len(tech) > 0}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = TechFingerprintTool
