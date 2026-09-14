import base64
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class Base64Tool(CyberToolPlugin):
    name = "base64_tool"
    description = "Encode or decode a string using Base64."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        action = (arguments.get("action") or "").strip().lower()
        string = arguments.get("string", "")
        if not action or not string:
            return {"success": False, "output": {}, "error": "Missing 'action' or 'string' argument."}
        try:
            if action == "encode":
                result = base64.b64encode(string.encode("utf-8")).decode("utf-8")
            elif action == "decode":
                result = base64.b64decode(string.encode("utf-8")).decode("utf-8")
            else:
                return {"success": False, "output": {}, "error": "Action must be 'encode' or 'decode'."}
            return {"success": True, "output": {"result": result}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = Base64Tool
