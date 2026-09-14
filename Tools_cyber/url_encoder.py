from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class UrlEncoderTool(CyberToolPlugin):
    name = "url_encoder"
    description = "Percent-encode and decode URL components."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from urllib.parse import quote, unquote
        value = arguments.get("value", "")
        mode = arguments.get("mode", "encode").lower()
        if not value:
            return {"success": False, "output": {}, "error": "Missing 'value' argument."}
        try:
            if mode == "decode":
                return {"success": True, "output": {"mode": "decode", "result": unquote(value)}, "error": ""}
            return {"success": True, "output": {"mode": "encode", "result": quote(value)}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = UrlEncoderTool
