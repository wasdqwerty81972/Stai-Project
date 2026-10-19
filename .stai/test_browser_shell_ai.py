"""
Combined AI test: Browser + Shell + File + Notes + Todos
AI searches, gets HTML, runs grep on it, saves findings.
"""
import os
import json
import time

from key_manager import AiApi
from Tools_cyber.browser_manager import BrowserManager
from Tools_cyber.web_search_tool import WebSearchTool
from Tools_cyber.open_url_tool import OpenUrlTool
from Tools_cyber.shell_exec import ShellExecTool
from Tools_cyber.sandbox_file_tools import SandboxFileTool
from Tools_cyber.notes_tool import NotesTool
from Tools_cyber.todo_tool import TodoTool

ai = AiApi(use_mock=False)
bm = BrowserManager.get_instance()

SYSTEM_PROMPT = """
You are SVS-Cyber, an autonomous cybersecurity investigation agent with these tools:
- web_search: Search the web via DuckDuckGo
- open_url: Open a URL and extract readable text
- get_html: Get raw HTML source of current page
- shell_exec: Run PowerShell/WSL/CMD commands (grep, find, etc.)
- file_tool: Read/write/append files
- notes: Create/list/delete investigation notes
- todo_write: Manage structured task lists
- screenshot: page.screenshot(path)

When using tools, output JSON like:
{"action": "call_tool", "tool": "tool_name", "arguments": {...}, "reasoning": "..."}
"""

def ai_chat(system: str, user: str) -> str:
    resp = ai.chat(system=system, user=user)
    return resp.choices[0].message.content

def take_screenshot(name: str):
    path = os.path.abspath(os.path.join(".stai", f"{name}.png"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    bm.page.screenshot(path=path)
    return path

print("=" * 70)
print("  SVS-Cyber: Browser + Shell + AI Combined Test")
print("=" * 70)

# --- Step 1: AI plans the investigation ---
print("\n--- STEP 1: AI Planning ---")
goal = """
Investigate the current top ransomware groups by:
1. Search for "ransomware groups 2025 top threats"
2. Open the most authoritative result
3. Get the raw HTML of that page
4. Save HTML to a file
5. Use shell grep to extract group names from the HTML
6. Save findings as notes and todos
"""
plan = ai_chat(SYSTEM_PROMPT, f"Plan this investigation step by step:\n{goal}")
print(f"AI Plan (truncated):\n{plan[:600]}...")

# --- Step 2: Search ---
print("\n--- STEP 2: Web Search ---")
ws = WebSearchTool()
search_result = ws.run({"query": "ransomware groups 2025 top threats site:breachsense.com OR site:securelist.com OR site:unit42.paloaltonetworks.com"})
print(f"Found {len(search_result.get('results', []))} results")
for i, r in enumerate(search_result.get("results", [])[:3]):
    print(f"  [{i+1}] {r['title'][:80]}")
    print(f"      {r['url'][:80]}")

take_screenshot("combined_search")

# --- Step 3: AI picks URL ---
print("\n--- STEP 3: AI selects URL ---")
results = search_result.get("results", [])
target_url = results[0]["url"] if results else "https://example.com"
# Clean DDG redirect
if "duckduckgo.com/l/?uddg=" in target_url:
    from urllib.parse import urlparse, parse_qs
    qs = parse_qs(urlparse(target_url).query)
    target_url = qs.get("uddg", [target_url])[0]
print(f"Opening: {target_url}")

# --- Step 4: Open URL + get HTML ---
print("\n--- STEP 4: Open URL & Get HTML ---")
ou = OpenUrlTool()
url_result = ou.run({"url": target_url})
print(f"Title: {url_result.get('title')}")
print(f"Text content: {len(url_result.get('content', ''))} chars")

html = bm.get_html()
print(f"Raw HTML: {len(html)} chars")

take_screenshot("combined_page_loaded")

# --- Step 5: Save HTML to file ---
print("\n--- STEP 5: Save HTML to file ---")
ft = SandboxFileTool()
ft.run({"action": "write", "path": "ransomware_page.html", "text": html})
print("HTML saved to ransomware_page.html")

# --- Step 6: Shell grep on HTML ---
print("\n--- STEP 6: Shell grep on HTML ---")
shell = ShellExecTool()
# Grep for common ransomware group patterns in the HTML
grep_result = shell.run({
    "command": r'grep -iE "lockbit|qilin|cl0p|blackcat|alphv|play|rhysida|8base|medusa|bianlian|akira|hunters" ransomware_page.html | head -30',
    "environment": "powershell"
})
print(f"Grep success: {grep_result.get('success')}")
print(f"Output:\n{grep_result.get('output', 'No matches')}")

# Also try a broader search
grep2 = shell.run({
    "command": r'grep -i "ransomware" ransomware_page.html | head -20',
    "environment": "powershell"
})
print(f"\nGrep 'ransomware':\n{grep2.get('output', '')[:500]}")

# --- Step 7: AI analyzes findings ---
print("\n--- STEP 7: AI analyzes findings ---")
analysis = ai_chat(SYSTEM_PROMPT, f"""
You searched for ransomware groups and got this HTML page.
The grep search for known ransomware groups returned:
{grep_result.get('output', 'No matches')}

The grep for 'ransomware' returned:
{grep2.get('output', '')[:1000]}

Analyze what groups were found or what the page contains.
Create a structured summary of ransomware groups/threats mentioned.
""")
print(f"AI Analysis:\n{analysis}")

# --- Step 8: Create note ---
print("\n--- STEP 8: Create investigation note ---")
nt = NotesTool()
nt.run({"action": "create", "title": "Ransomware Groups 2025 - Browser+Shell Investigation", "content": analysis})

# --- Step 9: Create todos ---
print("\n--- STEP 9: Create todo list ---")
tt = TodoTool()
tt.run({"todos": [
    {"id": "1", "text": "Search for ransomware groups 2025", "status": "completed"},
    {"id": "2", "text": "Open authoritative source page", "status": "completed"},
    {"id": "3", "text": "Extract HTML and save to file", "status": "completed"},
    {"id": "4", "text": "Grep HTML for ransomware group names", "status": "completed"},
    {"id": "5", "text": "Analyze findings and create note", "status": "completed"},
    {"id": "6", "text": "Cross-reference with threat intel feeds", "status": "pending"},
    {"id": "7", "text": "Generate final report", "status": "pending"},
], "merge": False})
print("Todos created")

# --- Step 10: Verify state ---
print("\n--- STEP 10: Verify persistent state ---")
with open(".stai/notes.json") as f:
    notes = json.load(f)
print(f"Notes: {len(notes)}")
for n in notes[-2:]:
    print(f"  - {n['title']} ({n['id']})")

with open(".stai/todos.json") as f:
    todos = json.load(f)
print(f"Todos: {len(todos)}")
for t in todos:
    print(f"  - {t['id']}: {t['text']} [{t['status']}]")

take_screenshot("combined_final")

print("\n=== COMBINED TEST COMPLETE ===")
print("Browser remains open for inspection. Press Ctrl+C to close.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    bm.close()
    print("Browser closed.")