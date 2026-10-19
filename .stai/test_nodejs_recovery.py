"""
Test: AI finds Node.js docs for async file read, recovers if first source insufficient.
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

SYSTEM_PROMPT = "You are SVS-Cyber, an autonomous research agent with web browsing tools. Do not ask the user for guidance."

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
print("  AI: Node.js Async File Read - Recovery Test")
print("=" * 70)

# --- Step 1: Initial search ---
print("\n--- Step 1: Initial search for Node.js docs ---")
sr1 = ws.run({"query": "Node.js latest version async file read documentation"})
take_screenshot("node_search1")
print(f"Found {len(sr1['results'])} results")
for r in sr1['results'][:5]:
    print(f"  -> {r['title'][:70]}: {clean_url(r['url'])[:80]}")

# --- Step 2: AI evaluates first result ---
print("\n--- Step 2: AI evaluates first result ---")
eval_prompt = f"""
Search results:
{json.dumps([{'title': r['title'], 'url': clean_url(r['url']), 'snippet': r.get('snippet','')[:200]} for r in sr1['results'][:5]], indent=2)}

Your task: Find the OFFICIAL Node.js documentation for the LATEST VERSION
that explains the RECOMMENDED way to read a file asynchronously.

Look at the first result. Does it directly answer the question? If not,
tell me what you need to do next. Do not ask me where to look.

Format:
EVALUATION: <sufficient/insufficient>
REASON: <why>
NEXT_ACTION: <what to do next>
"""

eval1 = ai_chat(SYSTEM_PROMPT, eval_prompt)
print(f"\nAI Evaluation:\n{eval1}")

# --- Step 3: AI decides next action ---
# Parse evaluation
if "insufficient" in eval1.lower() or "no" in eval1.lower() or "partial" in eval1.lower():
    print("\n--- Step 3: First result insufficient, searching again ---")
    
    # AI decides next search
    next_prompt = f"""
The first search didn't give enough info. You need to find the OFFICIAL Node.js 
documentation (nodejs.org or nodejs.org/docs) for the LATEST VERSION 
showing the RECOMMENDED async file read method.

Suggest the next search query to use. Output ONLY the query.
"""
    next_query = ai_chat(SYSTEM_PROMPT, next_prompt)
    print(f"\nAI Next Query: {next_query}")
    
    # Extract query
    query_match = re_mod.search(r'["\']([^"\']+)["\']', next_query)
    if not query_match:
        # Fallback
        next_query = "site:nodejs.org fs.promises readFile async latest version"
    else:
        next_query = query_match.group(1)
    
    # Execute second search
    print(f"\n--- Step 4: Second search ---")
    sr2 = ws.run({"query": next_query})
    take_screenshot("node_search2")
    print(f"Found {len(sr2['results'])} results")
    for r in sr2['results'][:5]:
        print(f"  -> {r['title'][:70]}: {clean_url(r['url'])[:80]}")
    
    # Evaluate second search
    eval2_prompt = f"""
Second search results:
{json.dumps([{'title': r['title'], 'url': clean_url(r['url']), 'snippet': r.get('snippet','')[:200]} for r in sr2['results'][:5]], indent=2)}

Do these results contain the official Node.js docs with the recommended 
async file read method for the latest version? If yes, pick the best URL.
If no, what would you search next?

Format:
EVALUATION: <sufficient/insufficient>
BEST_URL: <url or none>
NEXT_QUERY: <query or none>
"""
    eval2 = ai_chat(SYSTEM_PROMPT, eval2_prompt)
    print(f"\nAI Evaluation 2:\n{eval2}")
    
    # Parse best URL
    best_url = None
    if "insufficient" not in eval2.lower() or "best_url" in eval2.lower():
        url_match = re_mod.search(r'https?://[^\s<>"\]]+', eval2)
        if url_match:
            best_url = clean_url(url_match.group(0))
    
    if not best_url:
        # Try third search
        print("\n--- Step 5: Third search attempt ---")
        third_prompt = """
You need to find nodejs.org documentation for async file reading.
Suggest a precise search query for the official Node.js docs (nodejs.org/docs/latest/api/fs.html or similar).
Output ONLY the query.
"""
        third_query = ai_chat(SYSTEM_PROMPT, third_prompt)
        print(f"\nAI Third Query: {third_query}")
        
        q_match = re_mod.search(r'["\']([^"\']+)["\']', third_query)
        if q_match:
            third_query = q_match.group(1)
        else:
            third_query = "site:nodejs.org/docs/latest/api/fs.html readFile"
        
        sr3 = ws.run({"query": third_query})
        take_screenshot("node_search3")
        print(f"Found {len(sr3['results'])} results")
        for r in sr3['results'][:5]:
            print(f"  -> {r['title'][:70]}: {clean_url(r['url'])[:80]}")
        
        # Use the first nodejs.org result
        for r in sr3['results']:
            if 'nodejs.org' in clean_url(r['url']):
                best_url = clean_url(r['url'])
                break
    else:
        print(f"Best URL from search 2: {best_url}")
else:
    print("\n--- First result sufficient, using it ---")
    # Parse URL from first eval
    url_match = re_mod.search(r'https?://[^\s<>"\]]+', eval1)
    if url_match:
        best_url = clean_url(url_match.group(0))
    else:
        best_url = clean_url(sr1['results'][0]['url'])

# --- Step 6: Open the best URL ---
print(f"\n--- Step 6: Opening best source ---")
if best_url:
    ur = ou.run({"url": best_url})
    take_screenshot("node_best_source")
    title = ur.get("title", "")
    content = ur.get("content", "")
    print(f"Title: {title}")
    print(f"Content: {len(content)} chars")
    print(f"Preview: {content[:1000]}")
else:
    # Fallback
    best_url = "https://nodejs.org/docs/latest/api/fs.html"
    ur = ou.run({"url": best_url})
    take_screenshot("node_best_source")
    title = ur.get("title", "")
    content = ur.get("content", "")
    print(f"Using fallback: {best_url}")

# --- Step 7: AI extracts answer ---
print(f"\n--- Step 7: AI extracts answer from docs ---")
answer_prompt = f"""
Source: {best_url}
Title: {title}
Content (first 8000 chars):
{content[:8000]}

From this official Node.js documentation, what is the RECOMMENDED way to 
read a file asynchronously in the latest version?

Provide:
1. The exact method/function name
2. The module/import path
3. A minimal working example
4. Whether it uses promises/async-await or callbacks

Format:
METHOD: <name>
MODULE: <import path>
EXAMPLE: <code>
NOTES: <any important details>
"""

answer = ai_chat(SYSTEM_PROMPT, answer_prompt)
print(f"\nAI Final Answer:\n{answer}")
take_screenshot("node_final_answer")

# Save
nt.run({"action": "create", "title": "Node.js Async File Read Research", "content": f"Sources visited: {best_url}\n\n{answer}"})

with open("D:/STAI 2/.stai/nodejs_async_read.json", "w") as f:
    json.dump({
        "search_1": sr1,
        "search_2": sr2 if 'sr2' in locals() else None,
        "search_3": sr3 if 'sr3' in locals() else None,
        "final_source": best_url,
        "ai_answer": answer
    }, f, indent=2, default=str)

print(f"\n{'=' * 70}")
print("  TEST COMPLETE")
print(f"  Final source: {best_url}")
print(f"  Screenshots: .stai/node_*.png")
print(f"  Note: .stai/notes.json")
print(f"  Data: .stai/nodejs_async_read.json")
print(f"{'=' * 70}")

print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True: time.sleep(1)
except:
    bm.close()
    print("Browser closed.")