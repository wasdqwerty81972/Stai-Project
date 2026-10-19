import base64
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class Base32Tool(CyberToolPlugin):
    name = "base32_tool"
    description = "Encode and decode Base32 data."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        value = arguments.get("value", "")
        mode = arguments.get("mode", "encode").lower()
        if not value:
            return {"success": False, "output": {}, "error": "Missing 'value' argument."}
        try:
            if mode == "decode":
                decoded = base64.b32decode(value)
                return {"success": True, "output": {"mode": "decode", "result": decoded.decode("utf-8", errors="replace")}, "error": ""}
            encoded = base64.b32encode(value.encode("utf-8")).decode("utf-8")
            return {"success": True, "output": {"mode": "encode", "result": encoded}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = Base32Tool
