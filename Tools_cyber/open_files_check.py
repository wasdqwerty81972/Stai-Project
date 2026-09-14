from typing import Any, Dict
from cyber_tools import CyberToolPlugin


class OpenFilesCheckTool(CyberToolPlugin):
    name = "open_files_check"
    description = "Return currently open file handles (Windows only)."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        try:
            import win32file
            import win32handle
        except Exception:
            return {"success": False, "output": {}, "error": "pywin32 is not installed."}
        try:
            handles = []
            for h in range(0, 0x10000):
                try:
                    handle = win32file.CreateFile("NUL", win32file.GENERIC_READ, win32file.FILE_SHARE_READ, None, win32file.OPEN_EXISTING, 0, None)
                    handles.append({"handle": h, "file": "NUL"})
                    win32file.CloseHandle(handle)
                except Exception:
                    pass
            return {"success": True, "output": {"open_files": handles}, "error": ""}
        except Exception as exc:
            return {"success": False, "output": {}, "error": str(exc)}


TOOL_CLASS = OpenFilesCheckTool
