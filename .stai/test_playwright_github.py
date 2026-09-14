"""
Test: AI finds Playwright GitHub repo and extracts star count, language, license, latest release date.
"""
import os
import json
import time
import sys
import re

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
print("  AI Research: Playwright GitHub Repository Details")
print("=" * 70)

ws = WebSearchTool()
ou = OpenUrlTool()

# --- Step 1: Search for Playwright GitHub repo ---
print("\n--- Step 1: Search for Playwright GitHub repo ---")
sr = ws.run({"query": "Playwright microsoft GitHub official repository"})
take_screenshot("pw_search")

print(f"Found {len(sr['results'])} results")
for r in sr['results'][:5]:
    print(f"  -> {r['title'][:60]}: {r['url'][:90]}")

# Find the GitHub result
github_url = None
for r in sr['results']:
    if 'github.com' in r['url']:
        github_url = r['url']
        break
if not github_url:
    github_url = sr['results'][0]['url']

print(f"\nSelected: {github_url}")

# --- Step 2: Open the GitHub repo page ---
print(f"\n--- Step 2: Open GitHub repo page ---")
ur = ou.run({"url": github_url})
take_screenshot("pw_repo_page")

title = ur.get('title', '')
content = ur.get('content', '')
print(f"Title: {title}")
print(f"Content length: {len(content)} chars")

# Parse the URL to get the clean GitHub URL
if 'duckduckgo.com/l/?uddg=' in github_url:
    from urllib.parse import urlparse, parse_qs
    qs = parse_qs(urlparse(github_url).query)
    github_url = qs.get("uddg", [github_url])[0]
print(f"Clean URL: {github_url}")

repo_content = content[:5000]

# Extract data using regex
print("\n--- Step 3: Extracting repository details ---")

# Get raw HTML for more precise extraction
html = bm.get_html()
print(f"HTML length: {len(html)}")

# Search for star count
star_match = re.search(r'(\d+(?:[,.]\d+)*)\s*stars?', html, re.IGNORECASE)
if star_match:
    stars = star_match.group(1)
    print(f"Star count found: {stars}")
else:
    print("Star count: not directly found in HTML")

# Search for primary language
lang_match = re.search(r'language:["\s]*"([^"]+)"', html)
if not lang_match:
    # Try alternate patterns
    lang_match = re.search(r'(TypeScript|Python|JavaScript|Go|Rust|Java|C\+\+|HTML|CSS)', html[:5000])
    if lang_match:
        print(f"Language found: {lang_match.group(1)}")

# Search for license
license_match = re.search(r'license["\s>]*([A-Z][a-z]+(?:-[A-Z][a-z]+)*)', html)
if license_match:
    print(f"License found: {license_match.group(1)}")

# Search for release date
release_match = re.search(r'(\d{4}-\d{2}-\d{2})', html[:10000])
if release_match:
    print(f"Release date found: {release_match.group(1)}")

# --- Step 4: AI analyzes the GitHub page ---
print(f"\n--- Step 4: AI analyzes repository details ---")
analysis_prompt = f"""
You are analyzing a GitHub repository page for Microsoft Playwright.

Repository URL: {github_url}
Page Title: {title}
Page Content (first 5000 chars):
{repo_content}

From this page, extract the following information:
1. Current star count
2. Primary programming language
3. License type
4. Latest release date

Format your response as:
STARS: <number>
LANGUAGE: <language>
LICENSE: <license>
LATEST_RELEASE: <date>
"""

analysis = ai_chat(SYSTEM_PROMPT, analysis_prompt)
print(f"\nAI Response:\n{analysis}")

# --- Step 5: Save to notes ---
nt = NotesTool()
nt.run({"action": "create", "title": "Playwright GitHub Repo Analysis", "content": analysis[:2000]})
print("\nNote saved.")

# Save data file
with open("D:/STAI 2/.stai/playwright_github_data.json", "w") as f:
    json.dump({
        "url": github_url,
        "title": title,
        "content_preview": repo_content[:2000],
        "ai_analysis": analysis
    }, f, indent=2)

take_screenshot("pw_final_state")

print(f"\n{'=' * 70}")
print("  TEST COMPLETE")
print(f"{'=' * 70}")
print(f"Sources visited: GitHub repo page")
print(f"Screenshots: .stai/pw_*.png")
print(f"Data file: .stai/playwright_github_data.json")
print(f"Note saved to .stai/notes.json")

print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True: time.sleep(1)
except:
    bm.close()
    print("Browser closed.")