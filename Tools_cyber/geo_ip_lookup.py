from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class GeoIpLookupTool(CyberToolPlugin):
    name = "geo_ip_lookup"
    description = "Lookup geolocation data for an IP address."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        ip = arguments.get("ip", "")
        if not ip:
            return {"success": False, "output": {}, "error": "Missing 'ip' argument."}
        try:
            from urllib.request import urlopen
            from urllib.error import URLError
            with urlopen(f"https://ipapi.co/{ip}/json/", timeout=10) as resp:
                import json
                data = json.loads(resp.read().decode("utf-8"))
            return {"success": True, "output": data, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = GeoIpLookupTool
