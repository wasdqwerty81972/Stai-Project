from typing import Dict, Any
from urllib.parse import quote
from cyber_tools import CyberToolPlugin, RiskLevel
from Tools_cyber.browser_manager import BrowserManager

class WebSearchTool(CyberToolPlugin):
    name = "web_search"
    description = "Searches the web using DuckDuckGo via the persistent browser."
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        query = arguments.get("query")
        if not query:
            return {"error": "Missing query argument."}
            
        try:
            browser = BrowserManager.get_instance()
            search_url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
            browser.navigate(search_url)
            
            # Extract search results links and snippets
            results = browser.page.evaluate('''() => {
                const results = [];
                document.querySelectorAll('.result').forEach(el => {
                    const titleEl = el.querySelector('.result__title .result__a');
                    const snippetEl = el.querySelector('.result__snippet');
                    if (titleEl) {
                        results.push({
                            title: titleEl.innerText,
                            url: titleEl.href,
                            snippet: snippetEl ? snippetEl.innerText : ''
                        });
                    }
                });
                return results;
            }''')
            
            return {
                "success": True,
                "results": results
            }
        except Exception as e:
            return {"error": f"Search failed: {str(e)}"}

TOOL_CLASS = WebSearchTool
