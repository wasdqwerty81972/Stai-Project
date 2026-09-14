from typing import Any, Dict, List
from cyber_tools import CyberToolPlugin


class XssScannerTool(CyberToolPlugin):
    name = "xss_scanner"
    description = "Basic reflection-based XSS probe."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        url = arguments.get("url", "")
        method = arguments.get("method", "get").upper()
        param = arguments.get("param", "q")
        payload = arguments.get("payload", "<script>alert(1)</script>")
        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument."}
        try:
            if method == "POST":
                resp = requests.post(url, data={param: payload}, timeout=10)
            else:
                resp = requests.get(url, params={param: payload}, timeout=10)
            reflected = payload in resp.text
            return {"success": True, "output": {"url": url, "reflected": reflected, "status": resp.status_code}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = XssScannerTool
