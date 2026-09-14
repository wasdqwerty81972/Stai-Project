"""
Test: AI researches GitHub Copilot's browser/agent capabilities independently.
"""
import os
import json
import time
import sys
import re as re_mod

sys.stdout.reconfigure(encoding='utf-8')

from key_manager import AiApi
from Tools_cyber.browser_manager import BrowserManager
from Tools_cyber.web_search_tool import WebSearchTool
from Tools_cyber.open_url_tool import OpenUrlTool
from Tools_cyber.notes_tool import NotesTool
from urllib.parse import urlparse, parse_qs

ai = AiApi(use_mock=False)
bm = BrowserManager.get_instance()

SYSTEM_PROMPT = "You are SVS-Cyber, an autonomous research agent with web browsing tools. Decide searches and sources independently."

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
nt = NotesTool()

print("=" * 70)
print("  AI: GitHub Copilot Browser/Agent Capabilities Research")
print("=" * 70)

all_sources = {}

# --- Phase 1: Broad search ---
print("\n--- Search 1: GitHub Copilot agent capabilities ---")
sr1 = ws.run({"query": "GitHub Copilot agent browser capabilities features"})
take_screenshot("copilot_search1")
print(f"Found {len(sr1['results'])} results")
for r in sr1['results'][:5]:
    print(f"  -> {r['title'][:70]}: {clean_url(r['url'])[:80]}")
all_sources["search1"] = sr1

# --- Phase 2: Official docs ---
print("\n--- Search 2: Official GitHub Copilot documentation ---")
sr2 = ws.run({"query": "site:github.com GitHub Copilot agent mode browser"})
take_screenshot("copilot_search2")
print(f"Found {len(sr2['results'])} results")
for r in sr2['results'][:5]:
    print(f"  -> {r['title'][:70]}: {clean_url(r['url'])[:80]}")
all_sources["search2"] = sr2

# --- Phase 3: GitHub blog/changelog ---
print("\n--- Search 3: GitHub Copilot agent mode announcement ---")
sr3 = ws.run({"query": "GitHub Copilot agent mode launch announcement 2024 2025"})
take_screenshot("copilot_search3")
print(f"Found {len(sr3['results'])} results")
for r in sr3['results'][:5]:
    print(f"  -> {r['title'][:70]}: {clean_url(r['url'])[:80]}")
all_sources["search3"] = sr3

# --- Phase 4: AI selects key URLs ---
print("\n--- AI selects authoritative URLs ---")
search_summary = ""
for name, sr in all_sources.items():
    search_summary += f"\n{name}:\n"
    for r in sr['results'][:5]:
        search_summary += f"  - {r['title'][:80]} | {clean_url(r['url'])[:80]} | {r.get('snippet','')[:150]}\n"

select_prompt = f"""
From these search results, pick the 4-5 MOST AUTHORITATIVE URLs for understanding
GitHub Copilot's agent/browser capabilities. Prioritize:
- Official GitHub documentation (docs.github.com, github.blog)
- Official GitHub repositories (github/github, github/copilot)
- Authoritative technical articles

{search_summary}

Format:
1. <url>
2. <url>
3. <url>
4. <url>
5. <url>
"""

selection = ai_chat(SYSTEM_PROMPT, select_prompt)
print(f"\nAI Selected URLs:\n{selection}")
take_screenshot("copilot_selection")

# Parse URLs
urls = []
for line in selection.split("\n"):
    line = line.strip()
    match = re_mod.search(r'https?://[^\s<>"\]]+', line)
    if match:
        urls.append(match.group(0))

print(f"Parsed {len(urls)} URLs:")
for u in urls:
    print(f"  - {u}")

# --- Phase 5: Visit each URL ---
print(f"\n\n=== Visiting {len(urls)} sources ===")
source_data = {}
for i, url in enumerate(urls[:5], 1):
    print(f"\n=== Source {i}: {url} ===")
    try:
        ur = ou.run({"url": url})
        title = ur.get("title", "")
        content = ur.get("content", "")
        print(f"  Title: {title}")
        print(f"  Content: {len(content)} chars")
        take_screenshot(f"copilot_source_{i}")
        source_data[f"source_{i}"] = {
            "url": url,
            "title": title,
            "content": content[:5000]
        }
    except Exception as e:
        print(f"  Error: {e}")
        source_data[f"source_{i}"] = {"url": url, "error": str(e)}
    time.sleep(0.5)

# --- Phase 6: AI synthesizes report ---
print(f"\n\n=== AI Synthesis Report ===")

report_prompt = f"""
You researched GitHub Copilot's browser/agent capabilities by visiting these sources:

{json.dumps(source_data, indent=2)}

Based on the ACTUAL CONTENT from these sources, provide a CONCISE REPORT covering:

1. What is GitHub Copilot's agent mode / browser capability?
2. How does it work (architecture, tools)?
3. What browser/automation features does it have?
4. What's the current status/availability?
5. Key limitations or requirements

FORMAT:
## GITHUB COPILOT AGENT/BROWSER CAPABILITIES REPORT

### Overview
<2-3 sentences>

### How It Works
<technical details>

### Browser/Automation Capabilities
<specific features>

### Availability & Requirements
<who can use, prerequisites>

### Limitations
<key constraints>

### SOURCES USED
1. <url> - <what info it provided>
2. <url> - <what info it provided>
...
"""

report = ai_chat(SYSTEM_PROMPT, report_prompt)
print(f"\nAI Report:\n{report}")
take_screenshot("copilot_final_report")

# Save
nt.run({"action": "create", "title": "GitHub Copilot Agent Capabilities Research", "content": report[:5000]})

with open("D:/STAI 2/.stai/copilot_agent_research.json", "w") as f:
    json.dump({
        "searches": all_sources,
        "sources_visited": source_data,
        "report": report
    }, f, indent=2, default=str)

print(f"\n{'=' * 70}")
print("  TEST COMPLETE")
print(f"  Sources visited: {len(source_data)}")
for k, v in source_data.items():
    print(f"    - {v['url']} ({len(v.get('content',''))} chars)")
print(f"  Screenshots: .stai/copilot_*.png")
print(f"  Note: .stai/notes.json")
print(f"  Data: .stai/copilot_agent_research.json")
print(f"{'=' * 70}")

print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True: time.sleep(1)
except:
    bm.close()
    print("Browser closed.")