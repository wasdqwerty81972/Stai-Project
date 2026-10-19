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
