from typing import Dict, Any
from cyber_tools import CyberToolPlugin, RiskLevel
from Tools_cyber.browser_manager import BrowserManager

class OpenUrlTool(CyberToolPlugin):
    name = "open_url"
    description = "Opens a URL in the persistent browser and extracts its readable text."
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        url = arguments.get("url")
        if not url:
            return {"error": "Missing url argument."}
            
        try:
            browser = BrowserManager.get_instance()
            title = browser.navigate(url)
            content = browser.get_content()
            
            # Truncate content to avoid context overflow
            truncated = content[:30000] if len(content) > 30000 else content
            
            return {
                "success": True,
                "title": title,
                "content": truncated,
                "truncated": len(content) > 30000
            }
        except Exception as e:
            return {"error": f"Failed to open URL: {str(e)}"}

TOOL_CLASS = OpenUrlTool
