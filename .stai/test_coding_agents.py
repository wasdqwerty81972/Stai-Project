"""
Test: AI finds 3 open-source AI coding agents with browser automation, compares them.
AI must discover projects independently via web search.
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
from Tools_cyber.todo_tool import TodoTool
from urllib.parse import urlparse, parse_qs

ai = AiApi(use_mock=False)
bm = BrowserManager.get_instance()

SYSTEM_PROMPT = "You are SVS-Cyber, an autonomous cybersecurity research agent. You have web browsing tools. Make independent tool calls as needed."

def ai_chat(system: str, user: str) -> str:
    resp = ai.chat(system=system, user=user, temperature=0.3)
    return resp.choices[0].message.content

def take_screenshot(name: str):
    path = f"D:/STAI 2/.stai/{name}.png"
    bm.page.screenshot(path=path)
    return path

def clean_url(url):
    if "duckduckgo.com/l/?uddg=" in url:
        qs = parse_qs(urlparse(url).query)
        return qs.get("uddg", [url])[0]
    return url

ws = WebSearchTool()
ou = OpenUrlTool()

print("=" * 70)
print("  AI: Find 3 Open-Source AI Coding Agents with Browser Automation")
print("=" * 70)

all_sources = {}

# --- Search 1: Broad search ---
print("\n--- Search 1: Open-source AI coding agents browser automation ---")
sr1 = ws.run({"query": "open source AI coding agent browser automation playwright selenium"})
take_screenshot("ac_search1")
print(f"Found {len(sr1['results'])} results")
for r in sr1['results'][:5]:
    print(f"  -> {r['title'][:60]}: {r['url'][:70]}")

# --- Search 2: GitHub focused ---
print("\n--- Search 2: GitHub repos ---")
sr2 = ws.run({"query": "github.com open source AI coding agent browser automation"})
take_screenshot("ac_search2")
print(f"Found {len(sr2['results'])} results")
for r in sr2['results'][:5]:
    print(f"  -> {r['title'][:60]}: {r['url'][:70]}")

# --- Search 3: Specific tools ---
print("\n--- Search 3: Specific tools ---")
sr3 = ws.run({"query": "SWE-agent browser tool autonomous agent coding", })
take_screenshot("ac_search3")
print(f"Found {len(sr3['results'])} results")

sr4 = ws.run({"query": "OpenHands browser automation capabilities"})
take_screenshot("ac_search4")

sr5 = ws.run({"query": "AutoGPT browser plugin selenium puppeteer"})
take_screenshot("ac_search5")

# --- Combine search results and have AI identify candidates ---
print("\n--- AI identifies candidate projects ---")
search_summary = f"""
Search results from multiple searches:

Search 1 results (open source AI coding agent browser automation):
{json.dumps([{k: v[:150] for k, v in r.items()} for r in sr1['results'][:5]], indent=2)}

Search 2 results (GitHub repos):
{json.dumps([{k: v[:150] for k, v in r.items()} for r in sr2['results'][:5]], indent=2)}

Search 3 results (SWE-agent):
{json.dumps([{k: v[:150] for k, v in r.items()} for r in sr3['results'][:5]], indent=2)}

Search 4 results (OpenHands):
{json.dumps([{k: v[:150] for k, v in r.items()} for r in sr4['results'][:5]], indent=2)}

Search 5 results (AutoGPT):
{json.dumps([{k: v[:150] for k, v in r.items()} for r in sr5['results'][:5]], indent=2)}
"""

candidate_prompt = f"""
Based on these search results, identify the top 3 open-source AI coding agents
that support browser automation. For each, provide the name and official URL
(github.com or docs site). Only include projects that actually support browser
automation (via Playwright, Selenium, Puppeteer, etc.).

Format:
1. <name> - <url>
2. <name> - <url>
3. <name> - <url>
"""

# Add sources to all_sources
for i, sr in enumerate([sr1, sr2, sr3, sr4, sr5], 1):
    all_sources[f"search_{i}"] = sr

candidates_response = ai_chat(SYSTEM_PROMPT, search_summary + candidate_prompt)
print(f"\nAI Candidates:\n{candidates_response}")
take_screenshot("ac_candidates")

# --- Visit each candidate ---
print("\n\n=== Visiting Candidate Projects ===")
candidates = []
for line in candidates_response.split("\n"):
    line = line.strip()
    if line and (line[0].isdigit() or line.startswith("- ")):
        # Parse
        try:
            if "." in line[:3]:
                name_part = line.split(".", 1)[1].strip()
                parts = name_part.split(" - ", 1)
                if len(parts) == 2:
                    candidates.append((parts[0].strip(), parts[1].strip()))
        except:
            pass

# If parsing failed, manually extract URLs from the response
if not candidates:
    import re as re_mod
    urls = re_mod.findall(r'https?://[^\s<>"\]]+', candidates_response)
    candidates = [(f"Project {i+1}", url) for i, url in enumerate(urls[:3])]

print(f"\nFound {len(candidates)} candidates:")
for i, (name, url) in enumerate(candidates, 1):
    print(f"  {i}. {name}: {url}")

# Visit each candidate's main page and docs
project_data = {}
for i, (name, url) in enumerate(candidates[:3], 1):
    print(f"\n--- Visiting {name} ({url}) ---")

    # Search for the project first
    sr = ws.run({"query": f"{name} browser automation playwright selenium documentation"})
    take_screenshot(f"ac_{i}_search")

    # Visit the main page
    try:
        ur = ou.run({"url": url})
        title = ur.get("title", "")
        content = ur.get("content", "")
        print(f"  Title: {title}")
        print(f"  Content: {len(content)} chars")
        take_screenshot(f"ac_{i}_main")

        project_data[name] = {
            "url": url,
            "title": title,
            "content_preview": content[:3000],
            "search_query": f"{name} browser automation playwright selenium documentation"
        }
    except Exception as e:
        print(f"  Error: {e}")
        project_data[name] = {"url": url, "error": str(e)}

    # Also search for browser-specific docs
    search_query = name.lower().replace(" ", "")
    sr_browser = ws.run({"query": f"{name} browser tool playwright selenium puppeteer"})
    take_screenshot(f"ac_{i}_browser_search")
    print(f"  Browser search results: {len(sr_browser.get('results', []))}")

    browser_data = []
    for r in sr_browser.get("results", [])[:5]:
        browser_data.append({"title": r["title"][:100], "url": r["url"][:100], "snippet": r["snippet"][:200]})

        # Try to open some browser-related results
        if "browser" in r["title"].lower() or "browser" in r.get("snippet", "").lower():
            try:
                clean = clean_url(r["url"])
                ur2 = ou.run({"url": clean})
                if ur2.get("success"):
                    project_data[name].setdefault("browser_pages", []).append({
                        "url": clean,
                        "title": ur2.get("title", ""),
                        "content": ur2.get("content", "")[:3000]
                    })
                    take_screenshot(f"ac_{i}_browser_page")
                    break  # Just get one
            except:
                pass

    project_data[name]["browser_search_results"] = browser_data

# --- AI Comparison & Recommendation ---
print(f"\n\n=== AI Comparison & Recommendation ===")

comparison_data = json.dumps(project_data, indent=2)[:6000]
comparison_prompt = f"""
You identified and researched 3 open-source AI coding agents with browser automation:

{comparison_data}

For each project, summarize:
1. What browser automation they support (Playwright, Selenium, Puppeteer, native)
2. How they integrate it (built-in tool, plugin, extension)
3. Key features and limitations

Then recommend the strongest option with reasoning.

Format:
## Project 1: <name>
Browser Automation: <details>
Integration: <details>
Key Features: <details>
Limitations: <details>

## Project 2: <name>
...

## Project 3: <name>
...

## RECOMMENDATION
<project name> - <reasoning>
"""

recommendation = ai_chat(SYSTEM_PROMPT, comparison_prompt)
print(f"\nAI Comparison & Recommendation:\n{recommendation}")
take_screenshot("ac_final_recommendation")

# Save note
nt = NotesTool()
nt.run({"action": "create", "title": "AI Coding Agents Browser Automation Comparison", "content": recommendation[:4000]})

# Save data
with open("D:/STAI 2/.stai/coding_agents_comparison.json", "w") as f:
    json.dump({"candidates": candidates, "project_data": project_data, "recommendation": recommendation}, f, indent=2, default=str)

print(f"\n{'=' * 70}")
print("  TEST COMPLETE")
print(f"  Projects researched: {len(project_data)}")
print(f"  Screenshots: .stai/ac_*.png")
print(f"  Note: .stai/notes.json")
print(f"  Data: .stai/coding_agents_comparison.json")
print(f"{'=' * 70}")

print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True: time.sleep(1)
except:
    bm.close()
    print("Browser closed.")