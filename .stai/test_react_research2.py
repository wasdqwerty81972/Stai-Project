"""
Test: AI researches React version across 3+ independent sources.
Uses proper multi-turn conversation flow with tool results fed back as context.
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
from urllib.parse import urlparse, parse_qs

ai = AiApi(use_mock=False)
bm = BrowserManager.get_instance()

# Track interactions
search_count = 0
page_count = 0
visited_sources = []
tool_results_log = []

def ai_chat(system: str, conversation: list) -> str:
    """Call AI with a proper conversation history."""
    # Build a user message from the conversation history
    # The conversation is a list of alternating (role, content) tuples
    messages = []
    for role, content in conversation:
        messages.append(f"[{role.upper()}]: {content}")
    full_user = "\n\n".join(messages)
    resp = ai.chat(system=system, user=full_user, temperature=0.3)
    return resp.choices[0].message.content

def exec_tool(tool: str, args: dict) -> dict:
    """Execute a tool call and return the result."""
    global search_count, page_count

    if tool == "web_search":
        search_count += 1
        ws = WebSearchTool()
        result = ws.run(args)
        # Screenshot
        ts = int(time.time())
        bm.page.screenshot(path=f"D:/STAI 2/.stai/react_search_{ts}.png")
        # Extract result for context
        results = result.get("results", [])
        summary_parts = [f"Search returned {len(results)} results:"]
        for r in results[:5]:
            summary_parts.append(f"  - {r.get('title','')[:60]} | {r.get('url','')[:80]}")
        print(f"\n  [web_search #{search_count}] Query: {args.get('query','')}")
        print(f"  Results: {len(results)}")
        return {"result": result, "context": "\n".join(summary_parts)}

    elif tool == "open_url":
        page_count += 1
        url = args.get("url", "")
        original_url = url
        # Clean DDG redirect
        if "duckduckgo.com/l/?uddg=" in url:
            qs = parse_qs(urlparse(url).query)
            url = qs.get("uddg", [url])[0]
        visited_sources.append(url)
        ou = OpenUrlTool()
        result = ou.run(args)
        ts = int(time.time())
        safe = re.sub(r'[^a-zA-Z0-9]', '_', url[:40])
        bm.page.screenshot(path=f"D:/STAI 2/.stai/react_page_{safe}_{ts}.png")
        title = result.get('title', '')
        content = result.get('content', '')
        print(f"\n  [open_url #{page_count}] URL: {url}")
        print(f"  Title: {title}")
        print(f"  Content: {len(content)} chars")
        return {"result": result, "context": f"Opened: {url}\nTitle: {title}\nContent ({len(content)} chars): {content[:2000]}"}

    elif tool == "screenshot":
        name = args.get("name", "screenshot")
        path = f"D:/STAI 2/.stai/react_{name}.png"
        bm.page.screenshot(path=path)
        return {"result": {"success": True, "path": path}, "context": f"Screenshot saved: {path}"}

    elif tool == "notes":
        nt = NotesTool()
        result = nt.run(args)
        return {"result": result, "context": f"Note created: {result.get('note', {}).get('title', 'N/A')}"}

    elif tool == "todo_write":
        tt = TodoTool()
        result = tt.run(args)
        return {"result": result, "context": f"Todos updated: {result.get('stats', {})}"}

    return {"result": {"error": f"Unknown tool: {tool}"}, "context": f"Unknown tool: {tool}"}

SYSTEM_PROMPT = """
You are SVS-Cyber, an autonomous research agent with web browsing capabilities.
You have these tools: web_search, open_url, screenshot, notes, todo_write.
When you use a tool, output ONLY a JSON call:
{"action": "call_tool", "tool": "web_search", "arguments": {"query": "..."}}

I will execute your tool call and give you the result. Then you continue.
Visit at least 3 independent sources to verify findings.
"""

USER_TASK = """
Research the latest version of React. Search the web and check at least three
independent sources. Compare what they say, determine the most reliable answer,
and explain your conclusion with the sources you visited.

You MUST use web_search and open_url to actually browse. Visit at least 3
independent sources. Make one tool call at a time, examine the result, then
decide the next step. When you have enough information, provide your final
conclusion as plain text (no more tool calls).
"""

print("=" * 70)
print("  AI Research: Latest React Version from Multiple Sources")
print("=" * 70)

# Conversation history: list of (role, content) tuples
conversation = [("user", USER_TASK)]

max_rounds = 15
for round_num in range(1, max_rounds + 1):
    print(f"\n{'=' * 50}")
    print(f"ROUND {round_num}")
    print(f"{'=' * 50}")

    response = ai_chat(SYSTEM_PROMPT, conversation)
    print(f"AI: {response[:800]}")

    # Try to extract a tool call from the response
    # Look for JSON with call_tool action
    tool_call_match = None
    for pattern in [
        r'```json\s*(\{.*?"action".*?\})\s*```',
        r'(\{.*?"action"\s*:\s*"call_tool".*\})',
    ]:
        match = re.search(pattern, response, re.DOTALL)
        if match:
            tool_call_match = match.group(1) if match.lastindex else match.group(0)
            break

    if not tool_call_match:
        # Clean up attempt
        lines = response.strip().split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('{') and '"action"' in line:
                try:
                    json.loads(line)
                    tool_call_match = line
                    break
                except:
                    pass

    if tool_call_match:
        try:
            call = json.loads(tool_call_match)
            tool = call.get("tool")
            args = call.get("arguments", {})

            # Execute
            exec_result = exec_tool(tool, args)
            tool_results_log.append(exec_result)

            # Add to conversation
            conversation.append(("assistant", f"Called {tool} with {json.dumps(args)}"))
            conversation.append(("tool_result", exec_result["context"]))

            # Check progress
            if len(visited_sources) >= 3:
                # Add instruction to conclude
                conversation.append(("user", "You have visited 3+ sources. Now compare your findings and provide your final conclusion with the exact version number and all sources visited. Provide your final answer as plain text."))

        except json.JSONDecodeError as e:
            print(f"  JSON parse error: {e}")
            # Treat as final answer
            conversation.append(("assistant", response))
            break
    else:
        # No tool call = final answer
        conversation.append(("assistant", response))

        # Re-prompt for final answer if needed
        if page_count < 3 and len(visited_sources) < 3:
            print(f"\n  (AI gave text response but only visited {len(visited_sources)} sources)")
            conversation.append(("user", f"You have only visited {len(visited_sources)} source(s). You need at least 3. Please continue researching using web_search and open_url tools."))
            continue

        print(f"\n{'=' * 70}")
        print("  AI FINAL RESPONSE")
        print(f"{'=' * 70}")
        print(response)

        # Save
        nt = NotesTool()
        nt.run({"action": "create", "title": "React Version Research - Multi-Source", "content": response[:3000]})
        bm.page.screenshot(path="D:/STAI 2/.stai/react_final.png")

        break

print(f"\n{'=' * 70}")
print(f"  TEST SUMMARY")
print(f"{'=' * 70}")
print(f"Search calls: {search_count}")
print(f"Page openings: {page_count}")
print(f"Unique sources visited: {len(visited_sources)}")
for i, s in enumerate(visited_sources, 1):
    print(f"  Source {i}: {s}")

print(f"\nScreenshots: .stai/react_*.png")
print(f"Note saved to .stai/notes.json")

print("\nBrowser stays open. Press Ctrl+C to close.")
try:
    while True: time.sleep(1)
except:
    bm.close()
    print("Browser closed.")