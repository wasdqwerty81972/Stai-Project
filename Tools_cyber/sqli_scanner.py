from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class SqliScannerTool(CyberToolPlugin):
    name = "sqli_scanner"
    description = "Lightweight boolean-based SQLi fingerprint checks."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        url = arguments.get("url", "")
        param = arguments.get("param", "id")
        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument."}
        try:
            true_resp = requests.get(url, params={param: "1 AND 1=1"}, timeout=10)
            false_resp = requests.get(url, params={param: "1 AND 1=2"}, timeout=10)
            diff = abs(len(true_resp.text) - len(false_resp.text))
            return {
                "success": True,
                "output": {
                    "url": url,
                    "param": param,
                    "response_length_delta": diff,
                    "possible_sqli": diff > 50,
                },
                "error": "",
            }
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = SqliScannerTool
