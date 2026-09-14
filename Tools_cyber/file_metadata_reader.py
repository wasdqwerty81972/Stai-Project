import os
from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class FileMetadataReaderTool(CyberToolPlugin):
    name = "file_metadata_reader"
    description = "Return metadata for a filesystem path."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        filepath = arguments.get("file") or arguments.get("path", "")
        if not filepath:
            return {"success": False, "output": {}, "error": "Missing 'file' or 'path' argument."}
        try:
            stat = os.stat(filepath)
            return {"success": True, "output": {"path": filepath, "size_bytes": stat.st_size, "modified": stat.st_mtime}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = FileMetadataReaderTool
