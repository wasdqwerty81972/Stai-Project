from unittest.mock import Mock

from Tools_cyber.web_search_tool import WebSearchTool


def test_web_search_falls_back_to_bing_when_duckduckgo_has_no_results(monkeypatch):
    browser = Mock()
    browser.page.evaluate.side_effect = [
        {
            "title": "",
            "bodyText": "If this persists, please email us.",
            "results": [],
        },
        {
            "title": "Search results",
            "bodyText": "results",
            "results": [
                {
                    "title": "Useful result",
                    "url": "https://example.com/article",
                    "snippet": "Relevant information",
                }
            ],
        },
    ]
    monkeypatch.setattr(
        "Tools_cyber.web_search_tool.BrowserManager.get_instance",
        lambda: browser,
    )

    result = WebSearchTool().run({"query": "a useful search"})

    assert result["success"] is True
    assert result["provider"] == "Bing"
    assert result["results"][0]["url"] == "https://example.com/article"
    assert browser.navigate.call_count == 2


def test_web_search_reports_both_provider_failures(monkeypatch):
    browser = Mock()
    browser.page.evaluate.side_effect = [
        {"title": "", "bodyText": "blocked", "results": []},
        {"title": "", "bodyText": "blocked", "results": []},
    ]
    monkeypatch.setattr(
        "Tools_cyber.web_search_tool.BrowserManager.get_instance",
        lambda: browser,
    )

    result = WebSearchTool().run({"query": "a useful search"})

    assert result["success"] is False
    assert result["provider"] == "DuckDuckGo and Bing"
    assert "both" in result["error"].lower()
