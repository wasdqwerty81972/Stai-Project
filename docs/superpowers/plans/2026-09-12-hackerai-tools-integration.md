# HackerAI Tools Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the HackerAI tools (terminal, file, notes, todo, web_search, open_url) natively in Python for SVS-Cyber, introducing an OpenClaw-style persistent persistent Chromium browser for web interactions.

**Architecture:** We will implement the 8 HackerAI tools as native Python `CyberToolPlugin` subclasses inside the `Tools_cyber/` directory. Rather than dealing with complex cross-language IPC (TypeScript + Node.js bridge), we will use Python's `subprocess` for terminal execution, local filesystem for files/notes/todos, and `playwright-python` to launch a persistent, visible (or headless configurable) Chromium browser profile (`svs-cyber`) similar to OpenClaw.

**Tech Stack:** Python, Playwright (for browser), JSON (for notes/todos)

**Spec:** `docs/superpowers/specs/2026-09-12-hackerai-tools-design.md`

## Global Constraints

- Must work in the current SVS-Cyber Python environment.
- Tools must inherit from `CyberToolPlugin` and use the built-in JSON dict return model.
- Browser interactions must use a persistent context for session (cookie) stability.
- Use `RiskLevel` matching existing SVS-Cyber constraints.

---

### Task 1: Persistent Browser Automation (Dependencies & Manager)

**Files:**
- Create: `Tools_cyber/browser_manager.py`
- Modify: `requirements.txt` (or advise user to install deps)

**Interfaces:**
- Produces: `BrowserSession` class with methods `navigate(url)`, `get_page_content()`, `close()`.

- [ ] **Step 1: Write requirements instructions**
We'll assume the executor will ensure `playwright` is installed.
```bash
pip install playwright
playwright install chromium
```

- [ ] **Step 2: Implement BrowserManager**
Write `Tools_cyber/browser_manager.py` that provides a singleton-like `BrowserSession`.
```python
"""
OpenClaw-style browser session manager.
Provides a persistent Chromium profile for SVS-Cyber web interactions.
"""
import os
import atexit
from playwright.sync_api import sync_playwright, BrowserContext, Page

class BrowserManager:
    _instance = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.playwright = sync_playwright().start()
        profile_dir = os.path.abspath(os.path.join(".stai", "browser_profile"))
        os.makedirs(profile_dir, exist_ok=True)
        
        # Read headless toggle from env or default to False (visible)
        headless = os.environ.get("SVS_CYBER_HEADLESS", "false").lower() == "true"
        
        self.context: BrowserContext = self.playwright.chromium.launch_persistent_context(
            user_data_dir=profile_dir,
            headless=headless,
            viewport={"width": 1280, "height": 720},
            channel="chrome" if os.environ.get("USE_SYSTEM_CHROME") else None
        )
        self.page: Page = self.context.pages[0] if self.context.pages else self.context.new_page()
        atexit.register(self.close)

    def navigate(self, url: str):
        self.page.goto(url, wait_until="domcontentloaded")
        return self.page.title()

    def get_content(self):
        # Extract meaningful text, strip scripts/styles
        return self.page.evaluate('''() => {
            const clone = document.cloneNode(true);
            const remove = clone.querySelectorAll('script, style, noscript, svg, img, nav, footer');
            remove.forEach(el => el.remove());
            return clone.body ? clone.body.innerText : '';
        }''')

    def close(self):
        if hasattr(self, 'context') and self.context:
            self.context.close()
        if hasattr(self, 'playwright') and self.playwright:
            self.playwright.stop()
```

- [ ] **Step 3: Commit**
```bash
git add Tools_cyber/browser_manager.py
git commit -m "feat: add persistent browser manager via Playwright"
```

### Task 2: Web Search and Open URL Tools

**Files:**
- Create: `Tools_cyber/open_url_tool.py`
- Create: `Tools_cyber/web_search_tool.py`

**Interfaces:**
- Consumes: `BrowserManager` from `browser_manager.py`
- Produces: `OpenUrlTool` and `WebSearchTool` plugins

- [ ] **Step 1: Implement Open URL Tool**
Write `Tools_cyber/open_url_tool.py`.
```python
from typing import Dict, Any
from cyber_tools import CyberToolPlugin, RiskLevel
from Tools_cyber.browser_manager import BrowserManager

class OpenUrlTool(CyberToolPlugin):
    name = "open_url"
    description = "Opens a URL in the persistent browser and extracts its readable text."
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        url = arguments.get("url")
        if not url:
            return {"error": "Missing url argument."}
            
        try:
            browser = BrowserManager.get_instance()
            title = browser.navigate(url)
            content = browser.get_content()
            
            # Truncate content to avoid context overflow
            truncated = content[:30000] if len(content) > 30000 else content
            
            return {
                "success": True,
                "title": title,
                "content": truncated,
                "truncated": len(content) > 30000
            }
        except Exception as e:
            return {"error": f"Failed to open URL: {str(e)}"}

TOOL_CLASS = OpenUrlTool
```

- [ ] **Step 2: Implement Web Search Tool**
Write `Tools_cyber/web_search_tool.py`.
```python
from typing import Dict, Any
from urllib.parse import quote
from cyber_tools import CyberToolPlugin, RiskLevel
from Tools_cyber.browser_manager import BrowserManager

class WebSearchTool(CyberToolPlugin):
    name = "web_search"
    description = "Searches the web using DuckDuckGo via the persistent browser."
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        query = arguments.get("query")
        if not query:
            return {"error": "Missing query argument."}
            
        try:
            browser = BrowserManager.get_instance()
            search_url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
            browser.navigate(search_url)
            
            # Extract search results links and snippets
            results = browser.page.evaluate('''() => {
                const results = [];
                document.querySelectorAll('.result').forEach(el => {
                    const titleEl = el.querySelector('.result__title .result__a');
                    const snippetEl = el.querySelector('.result__snippet');
                    if (titleEl) {
                        results.append({
                            title: titleEl.innerText,
                            url: titleEl.href,
                            snippet: snippetEl ? snippetEl.innerText : ''
                        });
                    }
                });
                return results;
            }''')
            
            return {
                "success": True,
                "results": results
            }
        except Exception as e:
            return {"error": f"Search failed: {str(e)}"}

TOOL_CLASS = WebSearchTool
```

- [ ] **Step 3: Commit**
```bash
git add Tools_cyber/open_url_tool.py Tools_cyber/web_search_tool.py
git commit -m "feat: add open_url and web_search tools using playwright browser"
```

### Task 3: Local File Tools (Read, Write, Edit)

**Files:**
- Create: `Tools_cyber/sandbox_file_tools.py`

**Interfaces:**
- Produces: `SandboxFileTool` plugin replacing HackerAI's `file.ts`.

- [ ] **Step 1: Implement File Tool**
Write `Tools_cyber/sandbox_file_tools.py`.
```python
import os
from typing import Dict, Any
from cyber_tools import CyberToolPlugin, RiskLevel, _safe_workspace_path

class SandboxFileTool(CyberToolPlugin):
    name = "file_tool"
    description = "Read, write, append, or edit local files."
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    # write/append/edit require modification
    risk_level = RiskLevel.MODIFIES_SYSTEM

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        action = arguments.get("action")
        filepath = arguments.get("path")
        text = arguments.get("text", "")
        
        if not action or not filepath:
            return {"error": "Missing action or path."}
            
        try:
            path = _safe_workspace_path(".", filepath)
            
            if action == "read":
                if not os.path.exists(path):
                    return {"error": f"File not found: {filepath}"}
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read(1000000) # 1MB limit limit
                return {"success": True, "content": content}
                
            elif action == "write":
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                return {"success": True, "message": f"File written: {filepath}"}
                
            elif action == "append":
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "a", encoding="utf-8") as f:
                    f.write(text)
                return {"success": True, "message": f"File appended: {filepath}"}
                
            else:
                return {"error": f"Unsupported action: {action}"}
                
        except Exception as e:
            return {"error": str(e)}

TOOL_CLASS = SandboxFileTool
```

- [ ] **Step 2: Commit**
```bash
git add Tools_cyber/sandbox_file_tools.py
git commit -m "feat: add unified sandbox file operations tool"
```

### Task 4: Notes and Todo Tools (JSON Persistence)

**Files:**
- Create: `Tools_cyber/notes_tool.py`
- Create: `Tools_cyber/todo_tool.py`

**Interfaces:**
- Produces: `NotesTool` and `TodoTool` plugins.

- [ ] **Step 1: Implement Notes Tool**
Write `Tools_cyber/notes_tool.py`.
```python
import os
import json
import uuid
from datetime import datetime
from typing import Dict, Any
from cyber_tools import CyberToolPlugin, RiskLevel

class NotesTool(CyberToolPlugin):
    name = "notes"
    description = "Manage persistent investigation notes (create, list, update, delete)."
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY # Uses .stai/ internal state only

    def _get_notes_file(self):
        path = os.path.abspath(os.path.join(".stai", "notes.json"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, 'w') as f:
                json.dump([], f)
        return path

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        action = arguments.get("action", "list")
        notes_file = self._get_notes_file()
        
        with open(notes_file, 'r') as f:
            notes = json.load(f)
            
        if action == "list":
            return {"success": True, "notes": notes}
            
        elif action == "create":
            new_note = {
                "id": str(uuid.uuid4())[:8],
                "title": arguments.get("title", "Untitled"),
                "content": arguments.get("content", ""),
                "timestamp": datetime.now().isoformat()
            }
            notes.append(new_note)
            with open(notes_file, 'w') as f:
                json.dump(notes, f, indent=2)
            return {"success": True, "note": new_note}
            
        elif action == "delete":
            note_id = arguments.get("id")
            initial_len = len(notes)
            notes = [n for n in notes if n["id"] != note_id]
            if len(notes) < initial_len:
                with open(notes_file, 'w') as f:
                    json.dump(notes, f, indent=2)
                return {"success": True, "message": "Note deleted."}
            return {"error": "Note not found."}
            
        return {"error": "Unknown action."}

TOOL_CLASS = NotesTool
```

- [ ] **Step 2: Implement Todo Tool**
Write `Tools_cyber/todo_tool.py`.
```python
import os
import json
from typing import Dict, Any
from cyber_tools import CyberToolPlugin, RiskLevel

class TodoTool(CyberToolPlugin):
    name = "todo_write"
    description = "Manage structured task lists (todos) persistently."
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.READ_ONLY 

    def _get_todos_file(self):
        path = os.path.abspath(os.path.join(".stai", "todos.json"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, 'w') as f:
                json.dump([], f)
        return path

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        todos = arguments.get("todos", [])
        merge = arguments.get("merge", False)
        
        todos_file = self._get_todos_file()
        
        with open(todos_file, 'r') as f:
            existing = json.load(f)
            
        if not merge:
            # Overwrite completely
            final_todos = todos
        else:
            # Merge by ID
            existing_map = {t["id"]: t for t in existing}
            for new_t in todos:
                existing_map[new_t["id"]] = new_t
            final_todos = list(existing_map.values())
            
        with open(todos_file, 'w') as f:
            json.dump(final_todos, f, indent=2)
            
        stats = {
            "total": len(final_todos),
            "completed": sum(1 for t in final_todos if t.get("status") == "completed"),
            "in_progress": sum(1 for t in final_todos if t.get("status") == "in_progress")
        }
            
        return {
            "success": True, 
            "message": "Todos updated successfully.",
            "stats": stats,
            "currentTodos": final_todos
        }

TOOL_CLASS = TodoTool
```

- [ ] **Step 3: Commit**
```bash
git add Tools_cyber/notes_tool.py Tools_cyber/todo_tool.py
git commit -m "feat: add persistent markdown/JSON notes and todo tools"
```
