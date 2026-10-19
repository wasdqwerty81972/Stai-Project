from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class UrlValidatorTool(CyberToolPlugin):
    name = "url_validator"
    description = "Normalize and validate URL scheme, host, and optional port."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import urlparse
        url = arguments.get("url", "")
        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument."}
        try:
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            parsed = urlparse(url)
            valid = bool(parsed.scheme and parsed.netloc)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return {
                "success": True,
                "output": {
                    "url": url,
                    "valid": valid,
                    "scheme": parsed.scheme,
                    "host": parsed.hostname,
                    "port": port,
                    "path": parsed.path,
                },
                "error": "" if valid else "Invalid URL structure.",
            }
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = UrlValidatorTool
