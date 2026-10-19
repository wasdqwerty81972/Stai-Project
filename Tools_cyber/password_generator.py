import secrets
import string
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class PasswordGeneratorTool(CyberToolPlugin):
    name = "password_generator"
    description = "Generate a random password of specified length."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        length = int(arguments.get("length", 16))
        chars = string.ascii_letters + string.digits + "!@#$%^&*()-_"
        password = "".join(secrets.choice(chars) for _ in range(length))
        return {"success": True, "output": {"password": password, "length": len(password)}, "error": ""}


TOOL_CLASS = PasswordGeneratorTool
