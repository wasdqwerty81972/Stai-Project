from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class Rot13Tool(CyberToolPlugin):
    name = "rot13_tool"
    description = "Encode or decode ROT13 text."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import codecs
        value = arguments.get("value", "")
        if not value:
            return {"success": False, "output": {}, "error": "Missing 'value' argument."}
        try:
            result = codecs.encode(value, "rot_13")
            return {"success": True, "output": {"result": result}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = Rot13Tool
