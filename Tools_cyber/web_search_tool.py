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
            
            # Extract search results links and snippets. Search providers can
            # return a human-verification page to automated browsers; never
            # report that as a successful empty search, since that invites the
            # agent to answer current questions without evidence.
            search_page = browser.page.evaluate('''() => {
                const bodyText = document.body?.innerText || '';
                const results = [];
                document.querySelectorAll('.result').forEach(el => {
                    const titleEl = el.querySelector('.result__title .result__a');
                    const snippetEl = el.querySelector('.result__snippet');
                    if (titleEl) {
                        results.push({
                            title: titleEl.innerText.trim(),
                            url: titleEl.href,
                            snippet: snippetEl ? snippetEl.innerText.trim() : ''
                        });
                    }
                });
                return {title: document.title, bodyText, results};
            }''')

            results = search_page.get("results") or []
            body_text = search_page.get("bodyText", "")
            blocked_markers = (
                "Unfortunately, bots use DuckDuckGo",
                "Please complete the following challenge",
                "select all squares containing a duck",
            )
            if any(marker.casefold() in body_text.casefold() for marker in blocked_markers):
                results = []

            if not results:
                # DuckDuckGo intermittently serves an anti-bot/error page from
                # this persistent browser. Retry the same query through Bing
                # before reporting a failure to the agent.
                browser.navigate(f"https://www.bing.com/search?q={quote(query)}")
                bing_page = browser.page.evaluate('''() => {
                    const bodyText = document.body?.innerText || '';
                    const results = [];
                    document.querySelectorAll('li.b_algo').forEach(el => {
                        const titleEl = el.querySelector('h2 a');
                        const snippetEl = el.querySelector('.b_caption p, p');
                        if (titleEl) {
                            results.push({
                                title: titleEl.innerText.trim(),
                                url: titleEl.href,
                                snippet: snippetEl ? snippetEl.innerText.trim() : ''
                            });
                        }
                    });
                    return {title: document.title, bodyText, results};
                }''')
                results = bing_page.get("results") or []
                if not results:
                    return {
                        "success": False,
                        "provider": "DuckDuckGo and Bing",
                        "results": [],
                        "error": (
                            "Both DuckDuckGo and Bing returned no parseable search results. "
                            "No web results were retrieved; do not answer as if the search succeeded."
                        ),
                    }
                return {
                    "success": True,
                    "provider": "Bing",
                    "results": results,
                }
            
            return {
                "success": True,
                "provider": "DuckDuckGo",
                "results": results
            }
        except Exception as e:
            return {"error": f"Search failed: {str(e)}"}

TOOL_CLASS = WebSearchTool
