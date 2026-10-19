from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class JwtDecoderTool(CyberToolPlugin):
    name = "jwt_decoder"
    description = "Decode JWT header and payload without verification."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        import base64
        import json
        token = arguments.get("token", "")
        if not token:
            return {"success": False, "output": {}, "error": "Missing 'token' argument."}
        parts = token.split(".")
        if len(parts) < 2:
            return {"success": False, "output": {}, "error": "Token must have at least header.payload.signature."}
        header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        try:
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return {"success": True, "output": {"header": header, "payload": payload}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = JwtDecoderTool
