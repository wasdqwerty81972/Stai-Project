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
