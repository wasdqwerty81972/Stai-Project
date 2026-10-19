"""
Test: AI researches drag-and-drop file upload implementation via MDN and authoritative docs.
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

SYSTEM_PROMPT = "You are SVS-Cyber, an autonomous research agent with web browsing tools."

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
print("  AI: Research Drag-and-Drop File Upload (Native Browser APIs)")
print("=" * 70)

# --- Search MDN ---
print("\n--- Search 1: MDN drag and drop file upload ---")
sr1 = ws.run({"query": "site:developer.mozilla.org drag and drop file upload API"})
take_screenshot("dragdrop_search1")
print(f"Found {len(sr1['results'])} results")
for r in sr1['results'][:5]:
    print(f"  -> {r['title'][:70]}: {clean_url(r['url'])[:80]}")

# --- Search for File API ---
print("\n--- Search 2: MDN File API drag drop ---")
sr2 = ws.run({"query": "site:developer.mozilla.org FileReader drag drop file upload"})
take_screenshot("dragdrop_search2")
print(f"Found {len(sr2['results'])} results")
for r in sr2['results'][:5]:
    print(f"  -> {r['title'][:70]}: {clean_url(r['url'])[:80]}")

# --- Search for examples ---
print("\n--- Search 3: HTML5 drag drop file upload tutorial ---")
sr3 = ws.run({"query": "drag and drop file upload javascript tutorial HTML5"})
take_screenshot("dragdrop_search3")
print(f"Found {len(sr3['results'])} results")
for r in sr3['results'][:5]:
    print(f"  -> {r['title'][:70]}: {clean_url(r['url'])[:80]}")

# --- AI selects key URLs ---
print("\n--- AI selects authoritative URLs ---")
search_summary = f"""
Search 1 (MDN drag drop):
{json.dumps([{'title': r['title'], 'url': clean_url(r['url']), 'snippet': r.get('snippet','')[:150]} for r in sr1['results'][:5]], indent=2)}

Search 2 (MDN File API):
{json.dumps([{'title': r['title'], 'url': clean_url(r['url']), 'snippet': r.get('snippet','')[:150]} for r in sr2['results'][:5]], indent=2)}

Search 3 (Tutorials):
{json.dumps([{'title': r['title'], 'url': clean_url(r['url']), 'snippet': r.get('snippet','')[:150]} for r in sr3['results'][:5]], indent=2)}
"""

select_prompt = f"""
From these search results, pick the MOST AUTHORITATIVE 3-4 URLs for implementing
drag-and-drop file uploads using native browser APIs. Prioritize MDN (developer.mozilla.org)
and W3C standards. Provide exact URLs.

{search_summary}

Format:
1. <url>
2. <url>
3. <url>
4. <url>
"""

selection = ai_chat(SYSTEM_PROMPT, select_prompt)
print(f"\nAI Selected URLs:\n{selection}")
take_screenshot("dragdrop_selection")

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

# --- Visit each URL ---
print(f"\n\n=== Visiting {len(urls)} authoritative sources ===")
source_data = {}
for i, url in enumerate(urls[:4], 1):
    print(f"\n=== Source {i}: {url} ===")
    try:
        ur = ou.run({"url": url})
        title = ur.get("title", "")
        content = ur.get("content", "")
        print(f"  Title: {title}")
        print(f"  Content: {len(content)} chars")
        take_screenshot(f"dragdrop_source_{i}")
        source_data[f"source_{i}"] = {
            "url": url,
            "title": title,
            "content": content[:5000]
        }
    except Exception as e:
        print(f"  Error: {e}")
        source_data[f"source_{i}"] = {"url": url, "error": str(e)}
    time.sleep(0.5)

# --- AI provides implementation explanation and example ---
print(f"\n\n=== AI Implementation Explanation & Example ===")

comp_prompt = f"""
You researched drag-and-drop file upload implementation using these authoritative sources:

{json.dumps(source_data, indent=2)}

Based on the ACTUAL CONTENT from these sources, provide:

1. IMPLEMENTATION APPROACH: Explain the key native browser APIs involved
   (DataTransfer, FileList, FileReader, DragEvent, etc.) and the event flow.

2. WORKING EXAMPLE: A complete, minimal HTML/JS example that demonstrates
   drag-and-drop file upload with:
   - Drop zone element
   - Drag enter/leave/over/drop event handling
   - FileList processing
   - FileReader for reading file content
   - Display of file info/preview

Format:
## IMPLEMENTATION APPROACH
<detailed explanation>

## WORKING EXAMPLE
```html
<!DOCTYPE html>
<html>
...
```

Make sure the example is correct based on what you actually read in the sources.
"""

result = ai_chat(SYSTEM_PROMPT, comp_prompt)
print(f"\nAI Result:\n{result}")
take_screenshot("dragdrop_final")

# Save
nt.run({"action": "create", "title": "Drag-and-Drop File Upload Implementation", "content": result[:5000]})

with open("D:/STAI 2/.stai/dragdrop_implementation.json", "w") as f:
    json.dump({
        "sources": source_data,
        "ai_result": result
    }, f, indent=2, default=str)

print(f"\n{'=' * 70}")
print("  TEST COMPLETE")
print(f"  Sources visited: {len(source_data)}")
for k, v in source_data.items():
    print(f"    - {v['url']} ({len(v.get('content',''))} chars)")
print(f"  Screenshots: .stai/dragdrop_*.png")
print(f"  Note: .stai/notes.json")
print(f"  Data: .stai/dragdrop_implementation.json")
print(f"{'=' * 70}")

print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True: time.sleep(1)
except:
    bm.close()
    print("Browser closed.")