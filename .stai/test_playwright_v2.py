"""
Test v2: AI finds Playwright GitHub repo details from the main repo page.
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

SYSTEM_PROMPT = "You are SVS-Cyber, an autonomous research agent with web browsing capabilities."

def ai_chat(system: str, user: str) -> str:
    resp = ai.chat(system=system, user=user, temperature=0.3)
    return resp.choices[0].message.content

def take_screenshot(name: str):
    path = f"D:/STAI 2/.stai/{name}.png"
    bm.page.screenshot(path=path)
    return path

print("=" * 70)
print("  AI Research: Playwright GitHub Repo (Main Page)")
print("=" * 70)

ws = WebSearchTool()
ou = OpenUrlTool()

# Search
print("\n--- Step 1: Search for Playwright GitHub repo ---")
sr = ws.run({"query": "site:github.com microsoft playwright"})
take_screenshot("pw2_search")

# Find the main repo URL
github_url = None
for r in sr['results']:
    if 'github.com/microsoft/playwright' in r['url']:
        # Clean DDG redirect
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(r['url']).query)
        github_url = qs.get("uddg", [r['url']])[0]
        break

if not github_url:
    github_url = "https://github.com/microsoft/playwright"

# Remove /releases or /tags suffix if present
github_url = github_url.replace("/releases", "").replace("/tags", "")
print(f"Repo URL: {github_url}")

# --- Step 2: Navigate directly to the main repo page ---
print(f"\n--- Step 2: Open main GitHub repo page ---")
bm.navigate(github_url)
take_screenshot("pw2_main_repo")
time.sleep(1)

# Get the full page content
content = bm.get_content()
print(f"Content length: {len(content)}")

# Get HTML for regex extraction
html = bm.get_html()
print(f"HTML length: {len(html)}")

# --- Step 3: Extract details from main repo page ---
print("\n--- Step 3: AI extracts repository details ---")
analysis_prompt = f"""
Analyze the GitHub repository page for Microsoft Playwright.

Repository URL: {github_url}
Page content (first 6000 chars):
{content[:6000]}

Extract from this page:
1. Star count (e.g., "96k stars")
2. Primary programming language
3. License type (e.g., MIT, Apache-2.0)
4. Date of the latest release

Format:
STARS: <number>
LANGUAGE: <language>
LICENSE: <license>
LATEST_RELEASE_DATE: <date>
"""

analysis = ai_chat(SYSTEM_PROMPT, analysis_prompt)
print(f"\nAI Response:\n{analysis}")

# --- Step 4: Verify by also checking the releases page ---
print(f"\n--- Step 4: Cross-check with releases page ---")
releases_url = github_url + "/releases"
bm.navigate(releases_url)
take_screenshot("pw2_releases")
time.sleep(1)

release_content = bm.get_content()
print(f"Releases page content: {len(release_content)}")

# Extract release date from releases page
release_prompt = f"""
From the Playwright GitHub releases page, find the date of the most recent release.
Content:
{release_content[:3000]}

Format: LATEST_RELEASE_DATE: <date>
"""
release_analysis = ai_chat(SYSTEM_PROMPT, release_prompt)
print(f"\nRelease info:\n{release_analysis}")

# --- Step 5: Combine and save ---
combined = f"Playwright GitHub Repository Analysis\n\nRepo: {github_url}\n\nFrom main repo page:\n{analysis}\n\nFrom releases page:\n{release_analysis}"

nt = NotesTool()
nt.run({"action": "create", "title": "Playwright GitHub Repo Details V2", "content": combined[:3000]})

with open("D:/STAI 2/.stai/playwright_github_v2.json", "w") as f:
    json.dump({"repo": github_url, "main_page_analysis": analysis, "releases_page_analysis": release_analysis}, f, indent=2)

print(f"\n{'=' * 70}")
print("  TEST COMPLETE")
print(f"  Source: https://github.com/microsoft/playwright")
print(f"  Screenshot: .stai/pw2_*.png")
print(f"  Note: .stai/notes.json")
print(f"  Data: .stai/playwright_github_v2.json")
print(f"{'=' * 70}")

print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True: time.sleep(1)
except:
    bm.close()
    print("Browser closed.")