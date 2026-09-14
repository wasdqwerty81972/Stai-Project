"""Durable, JSON-backed state for autonomous investigations."""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class InvestigationState:
    """Small persistence boundary for one investigation run."""

    def __init__(self, root: str = ".sessions") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def create(self, objective: str, session_id: str = "default") -> Dict[str, Any]:
        investigation_id = f"inv-{datetime.now(timezone.utc):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:8]}"
        state = {
            "investigation_id": investigation_id,
            "session_id": session_id,
            "objective": objective,
            "status": "running",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "events": [],
            "tool_calls": [],
            "findings": [],
            "mitre": [],
            "decisions": [],
        }
        self.save(state)
        return state

    def save(self, state: Dict[str, Any]) -> None:
        with self._lock:
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
            path = self.root / f"{state['investigation_id']}.json"
            payload = json.dumps(state, indent=2, default=str)
            temporary = self.root / f".{state['investigation_id']}.{uuid.uuid4().hex}.tmp"
            try:
                temporary.write_text(payload, encoding="utf-8")
                os.replace(temporary, path)
            except OSError:
                recovery = self.root / f"{state['investigation_id']}.recovery.json"
                try:
                    recovery.write_text(payload, encoding="utf-8")
                except OSError:
                    pass
            finally:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

    def load(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        path = self.root / f"{investigation_id}.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None

    def append_event(self, investigation_id: str, event: Dict[str, Any]) -> bool:
        with self._lock:
            state = self.load(investigation_id)
            if state is None:
                return False
            state.setdefault("events", []).append(event)
            self.save(state)
            return True

    def recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        states = []
        for path in self.root.glob("inv-*.json"):
            state = self.load(path.stem)
            if state:
                states.append(state)
        return sorted(states, key=lambda item: item.get("updated_at", ""), reverse=True)[:limit]
