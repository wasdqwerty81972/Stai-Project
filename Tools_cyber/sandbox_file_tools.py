import os
from typing import Dict, Any
from cyber_tools import CyberToolPlugin, RiskLevel, _safe_workspace_path

class SandboxFileTool(CyberToolPlugin):
    name = "file_tool"
    description = "Read, write, append, or edit local files."
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    # write/append/edit require modification
    risk_level = RiskLevel.MODIFIES_SYSTEM

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        action = arguments.get("action")
        filepath = arguments.get("path")
        text = arguments.get("text", "")
        
        if not action or not filepath:
            return {"error": "Missing action or path."}
            
        try:
            path = _safe_workspace_path(".", filepath)
            
            if action == "read":
                if not os.path.exists(path):
                    return {"error": f"File not found: {filepath}"}
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read(1000000) # 1MB limit limit
                return {"success": True, "content": content}
                
            elif action == "write":
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                return {"success": True, "message": f"File written: {filepath}"}
                
            elif action == "append":
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "a", encoding="utf-8") as f:
                    f.write(text)
                return {"success": True, "message": f"File appended: {filepath}"}
                
            else:
                return {"error": f"Unsupported action: {action}"}
                
        except Exception as e:
            return {"error": str(e)}

TOOL_CLASS = SandboxFileTool
