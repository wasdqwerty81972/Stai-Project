from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class ElfAnalyzerTool(CyberToolPlugin):
    name = "elf_analyzer"
    description = "Basic ELF header and section inspection."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        filepath = arguments.get("filepath", "")
        if not filepath:
            return {"success": False, "output": {}, "error": "Missing 'filepath' argument."}
        try:
            with open(filepath, "rb") as f:
                data = f.read(64)
            is_elf = data[:4] == b"\x7fELF"
            if not is_elf:
                return {"success": False, "output": {}, "error": "File does not appear to be an ELF binary."}
            bits = "64-bit" if data[4] == 2 else "32-bit"
            return {
                "success": True,
                "output": {
                    "filepath": filepath,
                    "format": "ELF",
                    "class": bits,
                    "header_hex": data[:16].hex(),
                },
                "error": "",
            }
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = ElfAnalyzerTool
