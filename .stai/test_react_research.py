"""
Test: AI researches React version across 3+ independent sources.
Verifies AI performs multiple browser searches/pages before responding.
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
from Tools_cyber.todo_tool import TodoTool

ai = AiApi(use_mock=False)
bm = BrowserManager.get_instance()

SYSTEM_PROMPT = """
You are SVS-Cyber, an autonomous research agent.
You have these tools available via JSON calls:
- web_search: {"action": "call_tool", "tool": "web_search", "arguments": {"query": "..."}}
- open_url: {"action": "call_tool", "tool": "open_url", "arguments": {"url": "..."}}
- screenshot: {"action": "call_tool", "tool": "screenshot", "arguments": {"name": "..."}}
- notes: {"action": "call_tool", "tool": "notes", "arguments": {"action": "create", "title": "...", "content": "..."}}
- todo_write: {"action": "call_tool", "tool": "todo_write", "arguments": {"todos": [...], "merge": false}}

When you need to use a tool, output ONLY the JSON call on a single line.
I will execute it and return the result for you to continue reasoning.
"""

def ai_chat(system: str, user: str) -> str:
    resp = ai.chat(system=system, user=user)
    return resp.choices[0].message.content

def exec_tool(call_json: str):
    """Execute a tool call from AI JSON. Returns result as string for context."""
    # Clean the JSON
    cleaned = call_json.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned[7:]
    if cleaned.endswith("```"):
        cleaned = cleaned[:-3]
    call = json.loads(cleaned)
    tool = call.get("tool")
    args = call.get("arguments", {})

    if tool == "web_search":
        ws = WebSearchTool()
        result = ws.run(args)
        # Take screenshot of search results
        bm.page.screenshot(path=f"D:/STAI 2/.stai/react_search_{int(time.time())}.png")
        return result
    elif tool == "open_url":
        ou = OpenUrlTool()
        result = ou.run(args)
        # Take screenshot of opened page
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', args['url'][:50])
        bm.page.screenshot(path=f"D:/STAI 2/.stai/react_page_{safe_name}_{int(time.time())}.png")
        return result
    elif tool == "screenshot":
        name = args.get("name", "screenshot")
        bm.page.screenshot(path=f"D:/STAI 2/.stai/react_{name}.png")
        return {"success": True, "path": f".stai/react_{name}.png"}
    elif tool == "notes":
        nt = NotesTool()
        return nt.run(args)
    elif tool == "todo_write":
        tt = TodoTool()
        return tt.run(args)
    return {"error": f"Unknown tool: {tool}"}

def extract_tool_calls(text: str):
    """Extract JSON tool calls from AI response."""
    calls = []
    # Match JSON objects in the response
    matches = re.findall(r'\{[^{}]*"action"[^{}]*\}', text, re.DOTALL)
    for m in matches:
        try:
            call = json.loads(m)
            if "action" in call and call.get("action") == "call_tool":
                calls.append(call)
        except json.JSONDecodeError:
            pass
    # Also try matching from ```json blocks
    json_matches = re.findall(r'```json\s*(\{.*?\})\s*```', text, re.DOTALL)
    for m in json_matches:
        try:
            call = json.loads(m)
            if "action" in call:
                calls.append(call)
        except:
            pass
    return calls

print("=" * 70)
print("  AI Research: Latest React Version from Multiple Sources")
print("=" * 70)

USER_TASK = """
Research the latest version of React. Search the web and check at least three
independent sources. Compare what they say, determine the most reliable answer,
and explain your conclusion with the sources you visited.

You MUST use web_search and open_url tools to actually browse the web.
Visit at least 3 independent sources.
Before you start, create a todo list to track this research.
After each tool result, continue reasoning and make the next tool call.
When done, save your findings as a note and provide your final conclusion.
"""

# Initialize todos
tt = TodoTool()
tt.run({"todos": [
    {"id": "1", "text": "Search web for React latest version", "status": "pending"},
    {"id": "2", "text": "Visit source 1: react.dev (official)", "status": "pending"},
    {"id": "3", "text": "Visit source 2: npmjs.com", "status": "pending"},
    {"id": "4", "text": "Visit source 3: GitHub releases", "status": "pending"},
    {"id": "5", "text": "Compare findings and conclude", "status": "pending"},
], "merge": False})
print("Todo list created.")

# Track visited sources
visited_sources = []
search_count = 0
page_count = 0

# --- Round 1: AI searches ---
print("\n" + "=" * 50)
print("ROUND 1: Initial Search")
print("=" * 50)

context = ""
for round_num in range(1, 10):
    prompt = SYSTEM_PROMPT + f"\n\nTask:\n{USER_TASK}\n\nProgress so far:\n{context}"
    print(f"\n--- AI Round {round_num} ---")
    response = ai_chat("", prompt)
    print(f"AI Response:\n{response[:1000]}")

    calls = extract_tool_calls(response)
    if not calls:
        # AI is giving final answer
        print(f"\n=== AI FINAL ANSWER ===\n{response}")
        # Save as note
        nt = NotesTool()
        nt.run({"action": "create", "title": "React Version Research", "content": response[:3000]})
        bm.page.screenshot(path="D:/STAI 2/.stai/react_final_answer.png")
        print("\nNote saved. Screenshot: .stai/react_final_answer.png")
        break

    # Execute each tool call
    for call in calls:
        tool = call.get("tool")
        args = call.get("arguments", {})

        if tool == "web_search":
            search_count += 1
            print(f"\n[TOOL CALL {search_count}: web_search] Query: {args.get('query', '')}")
        elif tool == "open_url":
            page_count += 1
            url = args.get("url", '')
            if 'duckduckgo.com/l/?uddg=' in url:
                from urllib.parse import urlparse, parse_qs
                qs = parse_qs(urlparse(url).query)
                url = qs.get("uddg", [url])[0]
            visited_sources.append(url)
            print(f"\n[TOOL CALL {page_count}: open_url] URL: {url}")

        result = exec_tool(response)
        if isinstance(result, dict):
            # Summarize result for context
            if tool == "web_search":
                results = result.get("results", [])
                summary = f"Search returned {len(results)} results:\n"
                for r in results[:5]:
                    summary += f"  - {r.get('title','')[:60]}: {r.get('url','')[:80]}\n"
                context += f"\n[web_search result]: {summary}"
                print(f"  -> {len(results)} search results found")
            elif tool == "open_url":
                content = result.get("content", "")
                title = result.get("title", "")
                context += f"\n[open_url result]: Title={title}, Content length={len(content)}\n"
                context += f"Content preview: {content[:500]}\n"
                print(f"  -> Title: {title}, Content: {len(content)} chars")
            elif tool == "screenshot":
                context += f"\n[screenshot: {result.get('path','')}]\n"
            elif tool == "notes":
                context += f"\n[note: {result.get('success','')}]: {result.get('note',{})}\n"
            elif tool == "todo_write":
                context += f"\n[todos: {result.get('stats','')}]\n"

    # Show progress
    print(f"\nProgress: {search_count} search(es), {page_count} page(s) opened, {len(visited_sources)} unique sources visited")
    if len(visited_sources) >= 3:
        print("  -> Reached 3+ sources, AI will now compare and conclude")

    # Safety: limit rounds
    if round_num >= 8 and not calls:
        break

print(f"\n=== FINAL SUMMARY ===")
print(f"Search calls: {search_count}")
print(f"Page openings: {page_count}")
print(f"Unique sources visited: {len(visited_sources)}")
for i, s in enumerate(visited_sources, 1):
    print(f"  Source {i}: {s}")
print(f"\nAll React research screenshots: .stai/react_*.png")

print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True: time.sleep(1)
except: bm.close(); print("Browser closed.")