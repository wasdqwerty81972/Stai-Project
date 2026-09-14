import re
from typing import Any, Dict
import urllib.request
from cyber_tools import CyberToolPlugin


class HttpHeaderFetchTool(CyberToolPlugin):
    name = "http_header_fetch"
    description = "Fetch HTTP response headers from a URL."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        url = arguments.get("url", "")
        if not url:
            return {"success": False, "output": {}, "error": "Missing 'url' argument."}
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=10) as response:
                headers = dict(response.headers)
            return {"success": True, "output": {"headers": headers}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = HttpHeaderFetchTool
