from typing import Any, Dict, List
from cyber_tools import CyberToolPlugin


class XssScannerTool(CyberToolPlugin):
    name = "xss_scanner"
    description = "Harmless GET-only reflection probe; reflection alone does not prove executable XSS."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        url = arguments.get("url", "")
        param = arguments.get("param", "q")
        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument."}
        if not isinstance(param, str) or not param or len(param) > 64 or not all(
            (char.isascii() and char.isalnum()) or char in "_.-" for char in param
        ):
            return {"success": False, "output": {}, "error": "Invalid query parameter name."}
        try:
            # Never send executable markup or a state-changing POST request.
            # Disabling redirects keeps a server-provided Location from moving
            # this probe to a host outside the runtime's target scope.
            payload = "SVS_XSS_REFLECTION_PROBE"
            resp = requests.get(
                url,
                params={param: payload},
                timeout=10,
                allow_redirects=False,
            )
            reflected = payload in resp.text
            return {
                "success": True,
                "output": {
                    "url": url,
                    "reflected": reflected,
                    "status": resp.status_code,
                    "note": "Reflection is not proof of executable XSS.",
                },
                "error": "",
            }
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = XssScannerTool
