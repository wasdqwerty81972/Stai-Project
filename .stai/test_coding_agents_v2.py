"""
Test v2: Clean multi-source research of AI coding agents with browser automation.
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

SYSTEM_PROMPT = "You are SVS-Cyber, an autonomous cybersecurity research agent. You have web browsing tools."

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
print("  AI: 3 Open-Source AI Coding Agents with Browser Automation")
print("=" * 70)

# --- Phase 1: Search ---
print("\n--- Search Phase: Finding AI coding agents with browser automation ---")

queries = [
    "open source AI coding agent browser automation playwright",
    "SWE-agent OpenHands Skyvern browser automation",
    "GitHub browser-use agent playwright puppeteer",
]

all_search_results = {}
for i, q in enumerate(queries, 1):
    sr = ws.run({"query": q})
    take_screenshot(f"agent_search_{i}")
    all_search_results[f"search_{i}_{q[:30]}"] = sr
    print(f"\nSearch: {q}")
    print(f"  Found {len(sr['results'])} results")
    for r in sr['results'][:3]:
        print(f"  -> {r['title'][:60]}: {clean_url(r['url'])[:70]}")
    time.sleep(0.5)

# --- Phase 2: AI identifies 3 projects ---
print("\n--- Phase 2: AI identifies 3 projects ---")

# Build search summary
search_text = ""
for name, sr in all_search_results.items():
    search_text += f"\n\n{name}:\n"
    for r in sr['results'][:5]:
        search_text += f"  - {r['title'][:80]} | {clean_url(r['url'])[:80]} | {r.get('snippet','')[:150]}\n"

candidate_prompt = f"""
From these search results, identify the TOP 3 open-source AI coding agents
that have BROWSER AUTOMATION capabilities. For each, give the EXACT project
name and EXACT official GitHub URL or docs URL.

Search results:
{search_text}

Format your answer as:
PROJECT 1: <name> | <exact github.com or docs URL>
PROJECT 2: <name> | <exact github.com or docs URL>
PROJECT 3: <name> | <exact github.com or docs URL>
"""

candidates_resp = ai_chat(SYSTEM_PROMPT, candidate_prompt)
print(f"\nAI Candidates:\n{candidates_resp}")
take_screenshot("agent_candidates")

# Parse candidates more robustly
projects = []
for line in candidates_resp.split("\n"):
    line = line.strip()
    if line.startswith("PROJECT"):
        parts = line.split("|", 1)
        if len(parts) == 2:
            name = parts[0].split(":", 1)[1].strip()
            url = parts[1].strip()
            # Clean the URL
            url = re_mod.search(r'https?://[^\s<>"\]]+', url)
            if url:
                url = url.group(0)
            projects.append((name, url))
            print(f"  Parsed: {name} -> {url}")

if len(projects) < 3:
    print("  Warning: Could not parse 3 projects, trying regex extraction")
    urls = re_mod.findall(r'https?://[^\s<>"\]]+', candidates_resp)
    names = ["Project A", "Project B", "Project C"]
    for i, (name, url) in enumerate(zip(names, urls[:3])):
        projects.append((name, url))

# --- Phase 3: Visit each project ---
print(f"\n\n--- Phase 3: Visiting {len(projects)} projects ---")

project_details = {}
for i, (name, url) in enumerate(projects[:3], 1):
    print(f"\n=== Project {i}: {name} ({url}) ===")

    # Visit main page
    try:
        ur = ou.run({"url": url})
        title = ur.get("title", "")
        content = ur.get("content", "")
        print(f"  Main page: Title={title}, Content={len(content)} chars")
        take_screenshot(f"agent_{i}_main")
    except Exception as e:
        print(f"  Main page error: {e}")
        title, content = "", ""

    main_data = {
        "name": name,
        "url": url,
        "title": title,
        "content_preview": content[:4000]
    }

    # Search for browser automation docs
    browser_query = f"{name} browser automation playwright selenium documentation"
    sr_browser = ws.run({"query": browser_query})
    take_screenshot(f"agent_{i}_browser_search")
    print(f"  Browser search: {len(sr_browser['results'])} results")

    browser_docs = []
    for r in sr_browser['results'][:8]:
        clean = clean_url(r['url'])
        browser_docs.append({
            "title": r['title'][:100],
            "url": clean,
            "snippet": r.get('snippet', '')[:200]
        })

    # Try to open the most relevant browser doc
    for bd in browser_docs:
        if any(kw in bd['url'].lower() for kw in ['browser', 'playwright', 'selenium', 'puppeteer']):
            try:
                ur2 = ou.run({"url": bd['url']})
                if ur2.get("success"):
                    main_data["browser_doc_page"] = {
                        "url": bd['url'],
                        "title": ur2.get("title", ""),
                        "content": ur2.get("content", "")[:4000]
                    }
                    take_screenshot(f"agent_{i}_browser_doc")
                    print(f"  Opened browser doc: {ur2.get('title', '')[:50]}")
                    break
            except:
                pass

    project_details[name] = main_data
    time.sleep(0.5)

# --- Phase 4: AI compares and recommends ---
print("\n\n--- Phase 4: AI Comparison & Recommendation ---")

# Build comparison data
comp_data = []
for name, data in project_details.items():
    comp_data.append({
        "name": name,
        "url": data["url"],
        "title": data["title"],
        "main_content": data["content_preview"][:3000],
        "browser_doc": data.get("browser_doc_page", {}).get("content", "")[:3000],
        "browser_doc_title": data.get("browser_doc_page", {}).get("title", "")
    })

comparison_prompt = f"""
You researched 3 open-source AI coding agents with browser automation:

{json.dumps(comp_data, indent=2)}

For EACH project, provide:
1. Browser automation tool used (Playwright, Selenium, Puppeteer, custom)
2. How browser automation is integrated (built-in, plugin, library)
3. Key features for browser-based tasks
4. Limitations or constraints

Then give your RECOMMENDATION for the strongest option.

Format:
## Project 1: <name>
Browser Automation Tool: <tool>
Integration: <method>
Key Features: <list>
Limitations: <list>

## Project 2: <name>
...

## Project 3: <name>
...

## RECOMMENDATION
<name>
Reason: <detailed reasoning>
"""

recommendation = ai_chat(SYSTEM_PROMPT, comparison_prompt)
print(f"\nAI Recommendation:\n{recommendation}")
take_screenshot("agent_final_recommendation")

# Save
nt.run({"action": "create", "title": "AI Coding Agents Browser Automation Comparison", "content": recommendation[:4000]})

with open("D:/STAI 2/.stai/coding_agents_v2.json", "w") as f:
    json.dump({
        "projects": projects,
        "project_details": project_details,
        "recommendation": recommendation
    }, f, indent=2, default=str)

print(f"\n{'=' * 70}")
print("  TEST COMPLETE")
print(f"  Projects researched: {len(project_details)}")
for name, data in project_details.items():
    print(f"    - {name}: {data['url']}")
print(f"  Screenshots: .stai/agent_*.png")
print(f"  Note saved to .stai/notes.json")
print(f"  Data: .stai/coding_agents_v2.json")
print(f"{'=' * 70}")

print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True: time.sleep(1)
except:
    bm.close()
    print("Browser closed.")