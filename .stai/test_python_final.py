"""
Final test: AI finds Python version, outputs formatted answer.
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

SYSTEM_PROMPT = """You are SVS-Cyber. You have these tools via JSON:
- web_search: {"action": "call_tool", "tool": "web_search", "arguments": {"query": "..."}}
- open_url: {"action": "call_tool", "tool": "open_url", "arguments": {"url": "..."}}
- get_html: {"action": "call_tool", "tool": "get_html", "arguments": {}}

When you need a tool, output ONLY the JSON call."""

def ai_chat(system: str, user: str) -> str:
    resp = ai.chat(system=system, user=user)
    return resp.choices[0].message.content

def exec_tool(call_json: str):
    call = json.loads(call_json)
    tool = call.get("tool")
    args = call.get("arguments", {})
    if tool == "web_search":
        return WebSearchTool().run(args)
    elif tool == "open_url":
        return OpenUrlTool().run(args)
    elif tool == "get_html":
        return {"success": True, "html": bm.get_html()}
    return {"error": f"Unknown tool: {tool}"}

print("=" * 70)
print("  AI finds current stable Python version from official docs")
print("=" * 70)

# Step 1: Search
r1 = ai_chat(SYSTEM_PROMPT, "Search for the OFFICIAL Python documentation to find the CURRENT STABLE Python version. Use web_search.")
m = re.search(r'\{.*"tool":\s*"web_search".*\}', r1, re.DOTALL)
if m:
    sr = exec_tool(m.group(0))
    print(f"Search: {len(sr.get('results', []))} results")
    for i, r in enumerate(sr['results'][:3]):
        print(f"  {r['title'][:60]} -> {r['url'][:80]}")

# Step 2: Open official docs
r2 = ai_chat(SYSTEM_PROMPT, f"Results:\n{json.dumps([{'t':r['title'],'u':r['url']} for r in sr['results'][:5]])}\nPick the official docs.python.org URL. Output ONLY open_url JSON.")
m2 = re.search(r'\{.*"tool":\s*"open_url".*\}', r2, re.DOTALL)
if m2:
    ur = exec_tool(m2.group(0))
    content = ur.get('content', '')
    print(f"\nOpened: {ur.get('title')}")
    print(f"Content length: {len(content)}")
    print(f"Preview: {content[:500]}")

    # Step 3: Extract version
    r3 = ai_chat(SYSTEM_PROMPT, f"Page content:\n{content[:3000]}\n\nWhat is the CURRENT STABLE Python version? Answer in this exact format:\nVERSION: X.Y.Z\nURL: <url>\nEVIDENCE: <quote from page>")
    print(f"\nAI Answer:\n{r3}")

    # Save
    NotesTool().run({"action": "create", "title": "Python Version", "content": r3})
    bm.page.screenshot(path="D:/STAI 2/.stai/python_final.png")
    print("\nScreenshot: .stai/python_final.png")
    print("Note saved.")

print("\nDone. Browser open. Ctrl+C to close.")
try:
    while True: time.sleep(1)
except: bm.close()