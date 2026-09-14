import re
from typing import Any, Dict
from urllib.request import urlopen
from urllib.error import URLError
from cyber_tools import CyberToolPlugin


class UserAgentParserTool(CyberToolPlugin):
    name = "user_agent_parser"
    description = "Parse a User-Agent string and return a simplified browser/OS summary."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        ua = arguments.get("ua", "") or ""
        browser = "Unknown"
        if "Chrome" in ua and "Edg" not in ua:
            browser = "Chrome"
        elif "Firefox" in ua:
            browser = "Firefox"
        elif "Safari" in ua and "Chrome" not in ua:
            browser = "Safari"
        elif "Edg" in ua:
            browser = "Edge"
        return {"success": True, "output": {"user_agent": ua, "browser": browser}, "error": ""}


TOOL_CLASS = UserAgentParserTool
