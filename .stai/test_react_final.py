"""
Test: AI researches React version across 3+ independent sources.
Simplified approach: execute tools directly, AI analyzes each result.
"""
import os
import json
import time
import sys

sys.stdout.reconfigure(encoding='utf-8')

from key_manager import AiApi
from Tools_cyber.browser_manager import BrowserManager
from Tools_cyber.web_search_tool import WebSearchTool
from Tools_cyber.open_url_tool import OpenUrlTool
from Tools_cyber.notes_tool import NotesTool

ai = AiApi(use_mock=False)
bm = BrowserManager.get_instance()

SYSTEM_PROMPT = "You are SVS-Cyber, an autonomous research agent with web browsing capabilities. Provide clear, concise answers based on the data you are given."

def ai_chat(system: str, user: str) -> str:
    resp = ai.chat(system=system, user=user, temperature=0.3)
    return resp.choices[0].message.content

def take_screenshot(name: str):
    path = f"D:/STAI 2/.stai/{name}.png"
    bm.page.screenshot(path=path)
    return path

print("=" * 70)
print("  AI Research: Latest React Version from 3+ Sources")
print("=" * 70)

sources = {}

# --- Source 1: Search on DuckDuckGo ---
print("\n--- Source 1: DuckDuckGo Search ---")
ws = WebSearchTool()
sr = ws.run({"query": "React latest version official site:react.dev"})
take_screenshot("react_ddg_search")

print(f"Search returned {len(sr['results'])} results")
for r in sr['results'][:3]:
    print(f"  -> {r['title'][:60]}: {r['url'][:80]}")

# Find react.dev in results
react_dev_url = None
for r in sr['results']:
    if 'react.dev' in r['url'] or 'react.dev' in r.get('title', '').lower():
        react_dev_url = r['url']
        break
if not react_dev_url and sr['results']:
    react_dev_url = sr['results'][0]['url']

print(f"Selected URL: {react_dev_url}")

# --- Source 2: Open react.dev ---
print(f"\n--- Source 2: react.dev ---")
ou = OpenUrlTool()
ur = ou.run({"url": react_dev_url})
take_screenshot("react_react_dev")

title = ur.get('title', '')
content = ur.get('content', '')
print(f"Title: {title}")
print(f"Content: {len(content)} chars")
print(f"Preview: {content[:500]}")

sources["react_dev"] = {"url": react_dev_url, "title": title, "content": content[:5000]}

# --- Source 3: Search for npm registry version ---
print(f"\n--- Source 3: npm registry (JSON API) ---")
sr2 = ws.run({"query": "npm react latest version"})
take_screenshot("react_npm_search")

# Open npmjs.com/package/react
npm_url = "https://www.npmjs.com/package/react"
ur2 = ou.run({"url": npm_url})
take_screenshot("react_npm_page")

npm_content = ur2.get('content', '')
npm_title = ur2.get('title', '')
print(f"Title: {npm_title}")
print(f"Content: {len(npm_content)} chars")
print(f"Preview: {npm_content[:500]}")

sources["npm"] = {"url": npm_url, "title": npm_title, "content": npm_content[:5000]}

# --- Source 4: GitHub releases ---
print(f"\n--- Source 4: GitHub releases ---")
github_url = "https://github.com/facebook/react/releases"
ur3 = ou.run({"url": github_url})
take_screenshot("react_github_releases")

gh_content = ur3.get('content', '')
gh_title = ur3.get('title', '')
print(f"Title: {gh_title}")
print(f"Content: {len(gh_content)} chars")
print(f"Preview: {gh_content[:500]}")

sources["github"] = {"url": github_url, "title": gh_title, "content": gh_content[:5000]}

# --- AI Analysis: Compare all 4 sources ---
print(f"\n--- AI Analysis: Comparing Sources ---")

# Save HTML of all pages for inspection
all_content = ""
for name, data in sources.items():
    all_content += f"\n\n=== Source: {name} ===\nURL: {data['url']}\nTitle: {data['title']}\nContent: {data['content'][:2000]}"

# Get raw HTML from current page (GitHub releases) for grep testing
html = bm.get_html()
print(f"Current page HTML: {len(html)} chars")

# Search for version numbers in the HTML
import re as re_mod
version_patterns = re_mod.findall(r'(?:React|v)?\s*(\d+\.\d+\.\d+)', html)
print(f"Version patterns found in HTML: {version_patterns[:10]}")

# AI analysis
analysis_prompt = f"""
You are researching the latest stable version of React.js.

You have visited 4 independent sources:

SOURCE 1 - React.dev (Official docs):
URL: {sources['react_dev']['url']}
Title: {sources['react_dev']['title']}
Content: {sources['react_dev']['content'][:2000]}

SOURCE 2 - npmjs.com (npm registry):
URL: {sources['npm']['url']}
Title: {sources['npm']['title']}
Content: {sources['npm']['content'][:2000]}

SOURCE 3 - GitHub.com (official releases):
URL: {sources['github']['url']}
Title: {sources['github']['title']}
Content: {sources['github']['content'][:2000]}

SOURCE 4 - DuckDuckGo search results:
{sr['results'][0]['title']}: {sr['results'][0]['url']}
{sr['results'][0]['snippet'][:200]}

Based on all these sources, what is the current latest STABLE version of React?
Compare what each source says, identify any discrepancies, determine the most
reliable answer, and explain your conclusion.

Format your response as:
STABLE_VERSION: X.Y.Z
SOURCES_VISITED: 4
CONCLUSION: <detailed comparison and conclusion>
"""

analysis = ai_chat(SYSTEM_PROMPT, analysis_prompt)
print(f"\nAI Analysis:\n{analysis}")

# Save note
nt = NotesTool()
nt.run({"action": "create", "title": "React Version Research - Multi-Source", "content": analysis[:3000]})

# Save all source data to a file
with open("D:/STAI 2/.stai/react_research_data.json", "w") as f:
    json.dump(sources, f, indent=2)

# Final screenshots
take_screenshot("react_final_state")

print(f"\n{'=' * 70}")
print("  TEST COMPLETE")
print(f"{'=' * 70}")
print(f"Sources visited: {len(sources)}")
for name, data in sources.items():
    print(f"  - {name}: {data['url']}")
print(f"\nScreenshots: .stai/react_*.png")
print(f"Data file: .stai/react_research_data.json")
print(f"Note: .stai/notes.json")

print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True: time.sleep(1)
except:
    bm.close()
    print("Browser closed.")