import re
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class RegexTesterTool(CyberToolPlugin):
    name = "regex_tester"
    description = "Test a regex pattern against input text and return matches."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        pattern = arguments.get("pattern", "")
        text = arguments.get("input", "") or arguments.get("text", "")
        if not pattern:
            return {"success": False, "output": {}, "error": "Missing 'pattern' argument."}
        try:
            matches = re.findall(pattern, text)
            return {"success": True, "output": {"matches": matches, "count": len(matches)}, "error": ""}
        except re.error as exc:
            return {"success": False, "output": {}, "error": f"Invalid regex: {exc}"}


TOOL_CLASS = RegexTesterTool
