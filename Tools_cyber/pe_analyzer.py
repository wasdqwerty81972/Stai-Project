from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class PeAnalyzerTool(CyberToolPlugin):
    name = "pe_analyzer"
    description = "Extract basic PE metadata and suspicious import hints."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        filepath = arguments.get("filepath", "")
        if not filepath:
            return {"success": False, "output": {}, "error": "Missing 'filepath' argument."}
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            is_pe = data[:2] == b"MZ"
            if not is_pe:
                return {"success": False, "output": {}, "error": "File does not appear to be a PE."}
            suspicious = [name for name in [b"CreateRemoteThread", b"WriteProcessMemory", b"VirtualAlloc", b"ShellExecute", b"WinExec", b"URLDownloadToFile"] if name in data]
            return {
                "success": True,
                "output": {
                    "filepath": filepath,
                    "size": len(data),
                    "suspicious_imports": [s.decode("utf-8", errors="ignore") for s in suspicious],
                    "has_mz_header": True,
                },
                "error": "",
            }
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = PeAnalyzerTool
