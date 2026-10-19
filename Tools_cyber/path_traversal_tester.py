from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class PathTraversalTesterTool(CyberToolPlugin):
    name = "path_traversal_tester"
    description = "Test for basic path traversal exposure using common payloads."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        url = arguments.get("url", "")
        param = arguments.get("param", "file")
        payloads = arguments.get("payloads", ["../../../../etc/passwd", "..\\..\\..\\..\\Windows\\win.ini"])
        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument."}
        findings = []
        try:
            for payload in payloads:
                resp = requests.get(url, params={param: payload}, timeout=10)
                findings.append({"payload": payload, "status": resp.status_code, "length": len(resp.text)})
            return {"success": True, "output": {"url": url, "findings": findings}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = PathTraversalTesterTool
