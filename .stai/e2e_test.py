"""
End-to-end test: AI agent reasoning with HackerAI tools.
Browser stays open, AI searches, reasons, opens URLs, takes screenshots,
writes notes and todos.
"""
import json
import os
import time

from key_manager import AiApi
from Tools_cyber.browser_manager import BrowserManager
from Tools_cyber.web_search_tool import WebSearchTool
from Tools_cyber.open_url_tool import OpenUrlTool
from Tools_cyber.sandbox_file_tools import SandboxFileTool
from Tools_cyber.notes_tool import NotesTool
from Tools_cyber.todo_tool import TodoTool

ai = AiApi(use_mock=False)
bm = BrowserManager.get_instance()

SYSTEM_PROMPT = """
You are SVS-Cyber, an autonomous cybersecurity investigation agent.
You have access to these tools:
- web_search: Search the web via DuckDuckGo in a persistent browser
- open_url: Open a URL and extract readable text content
- file_tool: Read/write/append files in the workspace
- notes: Create/list/delete investigation notes (stored in .stai/notes.json)
- todo_write: Manage structured task lists (stored in .stai/todos.json)
- screenshot: Take a screenshot of the browser (use browser.page.screenshot)

When you use a tool, reason about the output before deciding the next step.
If you need to make multiple tool calls, list them as JSON.

Example response format when calling a tool:
{
  "action": "call_tool",
  "tool": "web_search",
  "arguments": {"query": "your search query"},
  "reasoning": "Why I'm doing this"
}
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
print("  SVS-Cyber AI Reasoning End-to-End Test")
print("=" * 70)
print(f"Browser profile: {os.path.abspath(os.path.join('.stai', 'browser_profile'))}")
print(f"Browser type: {'headless' if os.environ.get('SVS_CYBER_HEADLESS', 'false').lower() == 'true' else 'visible'}")
print()

# Step 1: AI reasons about the task and decides what to do
print("\n--- STEP 1: AI Planning ---")
goal = """
You are an autonomous cybersecurity agent. Your task is to:
1. Search the web for the latest ransomware attack trends in 2025
2. Open the most relevant result and read its content
3. Save key findings as investigation notes
4. Create a todo list tracking your investigation progress

For each action, explain your reasoning, then describe what you'll do next.
"""
plan = ai_chat(SYSTEM_PROMPT, goal)
print(f"AI Plan:\n{plan[:500]}")
print(f"... (truncated, full plan is {len(plan)} chars)")

# Step 2: AI decides to search the web
print("\n--- STEP 2: AI decides to search ---")
reasoning_prompt = """
You are SVS-Cyber, an autonomous cybersecurity agent.
Your task: Search the web for the latest ransomware attack trends in 2025.
First, decide if you should search or do something else.
Explain your reasoning in 2-3 sentences, then tell me the exact search query to use.
Format: REASONING: <your reasoning> | QUERY: <search query>
"""
decision = ai_chat(SYSTEM_PROMPT, reasoning_prompt)
print(f"AI Decision:\n{decision}")

# Extract query from AI response
if "QUERY:" in decision:
    query = decision.split("QUERY:")[1].strip().split("|")[0].strip()
else:
    query = "latest ransomware attack trends 2025"
print(f"\nSearching for: {query}")

# Step 3: Execute web search
print("\n--- STEP 3: Executing web_search ---")
ws = WebSearchTool()
search_result = ws.run({"query": query})
print(f"Search success: {search_result.get('success')}")
results = search_result.get("results", [])
print(f"Found {len(results)} search results")
for i, r in enumerate(results[:3]):
    print(f"  [{i+1}] {r.get('title', '')[:80]}")
    print(f"      URL: {r.get('url', '')[:80]}")
    print(f"      Snippet: {r.get('snippet', '')[:120]}")
    print()

# Take screenshot of search results page
shot_path = take_screenshot("search_results")
print(f"Screenshot saved: {shot_path}")

# Step 4: AI reasons about search results and picks a URL to open
print("\n--- STEP 4: AI reasoning about search results ---")
results_summary = json.dumps([{
    "title": r.get("title", ""),
    "url": r.get("url", ""),
    "snippet": r.get("snippet", "")[:200]
} for r in results[:5]], indent=2)

reasoning_prompt2 = f"""
You are SVS-Cyber, an autonomous cybersecurity agent.
Below are search results from a DuckDuckGo search for "latest ransomware attack trends 2025":

{results_summary}

Based on these results, which URL would be most valuable to open for detailed research on ransomware trends?
Explain your reasoning briefly, then state the exact URL to open.
Format: REASONING: <reasoning> | URL: <exact url>
"""
decision2 = ai_chat(SYSTEM_PROMPT, reasoning_prompt2)
print(f"AI Analysis:\n{decision2}")

# Extract URL
if "URL:" in decision2:
    target_url = decision2.split("URL:")[1].strip().split("\n")[0].strip()
else:
    target_url = results[0].get("url", "") if results else "https://example.com"
# Clean up DuckDuckGo redirect URLs
if "duckduckgo.com/l/?uddg=" in target_url:
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(target_url)
    qs = parse_qs(parsed.query)
    target_url = qs.get("uddg", [target_url])[0]
print(f"\nOpening: {target_url}")

# Step 5: Execute open_url
print("\n--- STEP 5: Executing open_url ---")
ou = OpenUrlTool()
url_result = ou.run({"url": target_url})
print(f"Open URL success: {url_result.get('success')}")
print(f"Title: {url_result.get('title', '')}")
content = url_result.get("content", "")
print(f"Content length: {len(content)}")
print(f"Truncated: {url_result.get('truncated', False)}")
print(f"Content preview:\n{content[:500]}")

# Screenshot the opened page
shot_path2 = take_screenshot("opened_article")
print(f"\nScreenshot saved: {shot_path2}")

# Step 6: AI analyzes the content and extracts key findings
print("\n--- STEP 6: AI analyzing content ---")
analysis_prompt = f"""
You are SVS-Cyber, an autonomous cybersecurity agent.
You have opened and read an article about ransomware trends.
Here is the extracted content (first 3000 chars):

{content[:3000]}

Analyze this content and extract the key ransomware trends/findings.
Present your findings as a structured analysis with:
1. Key ransomware trends identified
2. Any specific threat actors or groups mentioned
3. Attack techniques or vectors observed
4. Notable statistics or data points
"""
analysis = ai_chat(SYSTEM_PROMPT, analysis_prompt)
print(f"AI Analysis:\n{analysis}")

# Step 7: AI creates notes from findings
print("\n--- STEP 7: Creating investigation note ---")
nt = NotesTool()
note_result = nt.run({
    "action": "create",
    "title": "Ransomware Trends 2025 Investigation",
    "content": analysis[:2000]
})
print(f"Note created: {note_result.get('success')}")
print(f"Note ID: {note_result.get('note', {}).get('id')}")

# Step 8: AI creates todo list
print("\n--- STEP 8: Creating todo list ---")
tt = TodoTool()
todo_result = tt.run({
    "todos": [
        {"id": "1", "text": "Search web for ransomware trends 2025", "status": "completed"},
        {"id": "2", "text": "Open and analyze most relevant article", "status": "completed"},
        {"id": "3", "text": "Extract key findings and create investigation note", "status": "in_progress"},
        {"id": "4", "text": "Research specific threat actors mentioned", "status": "pending"},
        {"id": "5", "text": "Write final investigation report", "status": "pending"},
    ],
    "merge": False
})
print(f"Todos created: {todo_result.get('success')}")
print(f"Stats: {todo_result.get('stats')}")

# Step 9: List notes to verify
print("\n--- STEP 9: Verifying persistent state ---")
notes_list = nt.run({"action": "list"})
print(f"Notes in storage: {len(notes_list.get('notes', []))}")
for n in notes_list.get("notes", []):
    print(f"  - [{n['id']}] {n['title']} (created: {n['timestamp']})")

todos_file = os.path.join(".stai", "todos.json")
with open(todos_file, 'r') as f:
    stored_todos = json.load(f)
print(f"Todos in storage: {len(stored_todos)}")
for t in stored_todos:
    print(f"  - [{t['id']}] {t['text']} ({t['status']})")

# Final screenshot of the browser state
shot_path3 = take_screenshot("final_state")
print(f"\nFinal screenshot saved: {shot_path3}")

print("\n" + "=" * 70)
print("  TEST COMPLETE - Browser is still open for inspection")
print(f"  Screenshots: .stai/search_results.png, .stai/opened_article.png, .stai/final_state.png")
print(f"  Notes: .stai/notes.json")
print(f"  Todos: .stai/todos.json")
print("=" * 70)

# Don't close browser - let user inspect
print("\nBrowser remains open. Press Ctrl+C to close.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nClosing browser...")
    bm.close()
    print("Browser closed.")
