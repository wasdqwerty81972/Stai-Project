"""
Test: AI searches for official Python docs, finds current stable version.
Verifies AI actually uses browser tools, not training knowledge.
"""
import os
import json
import time
import sys

# Fix encoding for PowerShell
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
You are SVS-Cyber, an autonomous cybersecurity investigation agent.
You have access to these tools via JSON calls:
- web_search: {"action": "call_tool", "tool": "web_search", "arguments": {"query": "..."}}
- open_url: {"action": "call_tool", "tool": "open_url", "arguments": {"url": "..."}}
- get_html: {"action": "call_tool", "tool": "get_html", "arguments": {}}
- file_tool: {"action": "call_tool", "tool": "file_tool", "arguments": {"action": "write|read", "path": "...", "text": "..."}}
- notes: {"action": "call_tool", "tool": "notes", "arguments": {"action": "create|list", "title": "...", "content": "..."}}
- todo_write: {"action": "call_tool", "tool": "todo_write", "arguments": {"todos": [...], "merge": false}}

When you need to use a tool, output ONLY the JSON call.
I will execute it and return the result.
Then you continue reasoning.
"""

def ai_chat(system: str, user: str) -> str:
    resp = ai.chat(system=system, user=user)
    return resp.choices[0].message.content

def execute_tool_call(call_json: str):
    """Execute a tool call from AI JSON."""
    import json
    call = json.loads(call_json)
    tool = call.get("tool")
    args = call.get("arguments", {})
    
    if tool == "web_search":
        ws = WebSearchTool()
        return ws.run(args)
    elif tool == "open_url":
        ou = OpenUrlTool()
        return ou.run(args)
    elif tool == "get_html":
        return {"success": True, "html": bm.get_html()}
    elif tool == "file_tool":
        from Tools_cyber.sandbox_file_tools import SandboxFileTool
        ft = SandboxFileTool()
        return ft.run(args)
    elif tool == "notes":
        nt = NotesTool()
        return nt.run(args)
    elif tool == "todo_write":
        tt = TodoTool()
        return tt.run(args)
    return {"error": f"Unknown tool: {tool}"}

print("=" * 70)
print("  Test: AI Finds Official Python Version via Web Search")
print("=" * 70)

# --- AI searches ---
print("\n--- AI searches for Python docs ---")
search_prompt = f"""
{SYSTEM_PROMPT}

TASK: Search the web for the OFFICIAL Python documentation to find the CURRENT STABLE Python version.
You must use the web_search tool. Do not answer from your training knowledge.

First step: Use web_search to find the official Python documentation.
"""
response = ai_chat("", search_prompt)
print(f"AI Response:\n{response}")

# Check if AI called web_search
if "call_tool" in response and "web_search" in response:
    import re
    match = re.search(r'\{.*"tool":\s*"web_search".*\}', response, re.DOTALL)
    if match:
        result = execute_tool_call(match.group(0))
        print(f"\nWeb Search Result: {result.get('success')}")
        results = result.get("results", [])
        print(f"Found {len(results)} results")
        for i, r in enumerate(results[:5]):
            print(f"  [{i+1}] {r['title'][:80]}")
            print(f"      {r['url'][:100]}")
        
        # AI picks the best result
        print("\n--- AI selects official Python docs URL ---")
        select_prompt = f"""
Search results:
{json.dumps([{'title': r['title'], 'url': r['url'], 'snippet': r['snippet'][:200]} for r in results[:5]], indent=2)}

Which result is the OFFICIAL Python documentation (python.org)?
Output ONLY a JSON tool call to open_url with that URL.
"""
        response2 = ai_chat(SYSTEM_PROMPT, select_prompt)
        print(f"AI Selection:\n{response2}")
        
        match2 = re.search(r'\{.*"tool":\s*"open_url".*\}', response2, re.DOTALL)
        if match2:
            url_result = execute_tool_call(match2.group(0))
            print(f"\nOpen URL Result: {url_result.get('success')}")
            print(f"Title: {url_result.get('title')}")
            content = url_result.get('content', '')
            print(f"Content length: {len(content)}")
            print(f"Content preview:\n{content[:1500]}")
            
            # Save content to file to avoid encoding issues
            with open("D:/STAI 2/python_page_content.txt", "w", encoding="utf-8") as f:
                f.write(content)
            
            # AI extracts version
            print("\n--- AI extracts Python version ---")
            extract_prompt = f"""
Page content (first 3000 chars):
{content[:3000]}

What is the CURRENT STABLE Python version shown on this page?
Also provide the exact URL of this page.
Format your answer as:
VERSION: X.Y.Z
URL: <exact url>
EVIDENCE: <quote from page showing version>
"""
            response3 = ai_chat(SYSTEM_PROMPT, extract_prompt)
            print(f"AI Answer:\n{response3}")
            
            # Save note
            nt = NotesTool()
            nt.run({"action": "create", "title": "Python Version Research", "content": f"AI Research:\n{response3}\n\nSource page content preview:\n{content[:2000]}"})
            
            # Screenshot
            bm.page.screenshot(path="D:/STAI 2/.stai/python_docs_test.png")
            print("\nScreenshot saved to .stai/python_docs_test.png")
            
            # Verify
            if "3." in response3 and "python.org" in response3.lower():
                print("\nVERIFIED: AI used browser tools and found info from live page")
            else:
                print("\nCould not fully verify - check AI answer")
        else:
            print("AI did not output open_url tool call")
    else:
        print("AI did not output web_search tool call - may have answered from knowledge")
        print("Response was:", response[:500])
else:
    print("AI did not use web_search tool - answered from training knowledge")

print("\n=== Test Complete ===")
print("Browser stays open. Press Ctrl+C to close.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    bm.close()
    print("Browser closed.")