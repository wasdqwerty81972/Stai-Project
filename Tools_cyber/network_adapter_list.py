import os
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class NetworkAdapterListTool(CyberToolPlugin):
    name = "network_adapter_list"
    description = "List network adapter names and MAC addresses."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            import netifaces
        except Exception:
            return {"success": False, "output": {}, "error": "netifaces is not installed."}
        try:
            interfaces = netifaces.interfaces()
            result = []
            for iface in interfaces:
                addrs = netifaces.ifaddresses(iface)
                mac = addrs.get(netifaces.AF_LINK, [{}])[0].get("addr")
                ipv4 = addrs.get(netifaces.AF_INET, [{}])[0].get("addr")
                result.append({"interface": iface, "mac": mac, "ipv4": ipv4})
            return {"success": True, "output": {"adapters": result}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = NetworkAdapterListTool
