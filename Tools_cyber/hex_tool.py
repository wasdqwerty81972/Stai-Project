from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class HexTool(CyberToolPlugin):
    name = "hex_tool"
    description = "Encode and decode hex strings."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        value = arguments.get("value", "")
        mode = arguments.get("mode", "encode").lower()
        if not value:
            return {"success": False, "output": {}, "error": "Missing 'value' argument."}
        try:
            if mode == "decode":
                decoded = bytes.fromhex(value)
                return {"success": True, "output": {"mode": "decode", "result": decoded.decode("utf-8", errors="replace")}, "error": ""}
            encoded = value.encode("utf-8").hex()
            return {"success": True, "output": {"mode": "encode", "result": encoded}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = HexTool
