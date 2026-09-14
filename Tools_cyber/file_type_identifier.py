from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class FileTypeIdentifierTool(CyberToolPlugin):
    name = "file_type_identifier"
    description = "Identify file type from magic bytes."
    version = "1.0.0"
    risk_level = CyberToolPlugin.risk_level

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        filepath = arguments.get("filepath", "")
        if not filepath:
            return {"success": False, "output": {}, "error": "Missing 'filepath' argument."}
        try:
            with open(filepath, "rb") as f:
                header = f.read(16)
            signatures = {
                b"\x89PNG\r\n\x1a\n": "PNG image",
                b"%PDF": "PDF document",
                b"PK\x03\x04": "ZIP-based (docx/xlsx/zip/jar)",
                b"\x50\x4b\x03\x04": "ZIP archive",
                b"\x1f\x8b": "GZIP",
                b"\x42\x5a\x68": "BZIP2",
                b"\x75\x73\x74\x61\x72": "TAR archive",
                b"\x49\x44\x33": "MP3",
                b"\xff\xd8\xff": "JPEG image",
                b"GIF87a": "GIF image",
                b"GIF89a": "GIF image",
                b"<!DOCTYPE html": "HTML document",
                b"<!DOCTYPE HTML": "HTML document",
                b"<?xml": "XML document",
                b"{\n": "JSON text",
                b"{": "JSON text",
            }
            detected = "Unknown binary"
            for magic, label in signatures.items():
                if header.startswith(magic):
                    detected = label
                    break
            return {"success": True, "output": {"filepath": filepath, "file_type": detected, "header_hex": header.hex()}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = FileTypeIdentifierTool
