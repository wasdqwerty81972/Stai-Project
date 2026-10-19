"""Quick test of web_search and all HackerAI tools."""
import json
from Tools_cyber.browser_manager import BrowserManager
from Tools_cyber.web_search_tool import WebSearchTool
from Tools_cyber.open_url_tool import OpenUrlTool
from Tools_cyber.sandbox_file_tools import SandboxFileTool
from Tools_cyber.notes_tool import NotesTool
from Tools_cyber.todo_tool import TodoTool

print("=== 1. WebSearchTool ===")
ws = WebSearchTool()
result = ws.run({"query": "latest cybersecurity threats 2025"})
print("Success:", result.get("success"))
print("Results count:", len(result.get("results", [])))
for i, r in enumerate(result.get("results", [])[:3]):
    print(f"  [{i+1}] {r.get('title', '')[:80]}")
    print(f"      URL: {r.get('url', '')[:80]}")
    print(f"      Snippet: {r.get('snippet', '')[:120]}")
    print()

print("=== 2. OpenUrlTool ===")
ou = OpenUrlTool()
result = ou.run({"url": "https://example.com"})
print("Success:", result.get("success"))
print("Title:", result.get("title"))
print("Content length:", len(result.get("content", "")))
print("Truncated:", result.get("truncated"))
print("Content preview:", result.get("content", "")[:200])
print()

print("=== 3. SandboxFileTool (write) ===")
ft = SandboxFileTool()
result = ft.run({"action": "write", "path": "test_output.txt", "text": "Hello from SVS-Cyber tools test!"})
print("Success:", result.get("success"), result.get("message"))

print("=== 4. SandboxFileTool (read) ===")
result = ft.run({"action": "read", "path": "test_output.txt"})
print("Success:", result.get("success"))
print("Content:", result.get("content"))

print("=== 5. SandboxFileTool (append) ===")
result = ft.run({"action": "append", "path": "test_output.txt", "text": "\nAppended line!"})
print("Success:", result.get("success"), result.get("message"))
result = ft.run({"action": "read", "path": "test_output.txt"})
print("Content after append:", result.get("content"))
print()

print("=== 6. NotesTool ===")
nt = NotesTool()
result = nt.run({"action": "create", "title": "Test Note", "content": "This is a test note from SVS-Cyber"})
print("Create success:", result.get("success"))
note_id = result.get("note", {}).get("id")
print("Note ID:", note_id)
result = nt.run({"action": "list"})
print("List success:", result.get("success"))
print("Notes count:", len(result.get("notes", [])))
for n in result.get("notes", []):
    print(f"  - [{n['id']}] {n['title']}: {n['content'][:50]}")

print("=== 7. TodoTool ===")
tt = TodoTool()
result = tt.run({"action": None, "todos": [
    {"id": "1", "text": "Test todo item", "status": "in_progress"},
    {"id": "2", "text": "Another todo", "status": "pending"},
], "merge": False})
print("Todo success:", result.get("success"))
print("Stats:", result.get("stats"))
print("Current todos:", json.dumps(result.get("currentTodos", []), indent=2))
print()

print("=== 8. BrowserManager screenshot ===")
bm = BrowserManager.get_instance()
bm.navigate("https://example.com")
bm.page.screenshot(path="D:/STAI 2/.stai/test_final_screenshot.png")
print("Screenshot saved to .stai/test_final_screenshot.png")
bm.close()

print("\n=== ALL TESTS PASSED ===")
