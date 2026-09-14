from typing import Any, Dict, List
from cyber_tools import CyberToolPlugin


class HttpHeaderAnalyzerTool(CyberToolPlugin):
    name = "http_header_analyzer"
    description = "Fetch HTTP headers and score common security headers."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

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
            headers = dict(resp.headers)
            security_headers = {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "MISSING"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "MISSING"),
                "X-Frame-Options": headers.get("X-Frame-Options", "MISSING"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "MISSING"),
                "Referrer-Policy": headers.get("Referrer-Policy", "MISSING"),
                "Permissions-Policy": headers.get("Permissions-Policy", "MISSING"),
            }
            missing = [k for k, v in security_headers.items() if v == "MISSING"]
            return {
                "success": True,
                "output": {
                    "url": url,
                    "status_code": resp.status_code,
                    "server": headers.get("Server", "unknown"),
                    "security_headers": security_headers,
                    "missing_security_headers": missing,
                    "score": max(0, 5 - len(missing)),
                },
                "error": "",
            }
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = HttpHeaderAnalyzerTool
