"""
cyber_os/task_manager.py — Investigation Task & TODO Tracker for SVS-Cyber

Provides persistent, real-time tracking of investigation tasks and subagent assignments.
Emits live UI events for plan progress visualization.
Adapted from mature agent task-management architecture for SVS-Cyber.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ui.event_bus import AgentEvent, event_bus


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


@dataclass
class InvestigationTask:
    task_id: str
    title: str
    status: TaskStatus = TaskStatus.PENDING
    assigned_to: str = "main_agent"
    details: str = ""
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.task_id,
            "title": self.title,
            "status": self.status.value if isinstance(self.status, TaskStatus) else str(self.status),
            "assigned_to": self.assigned_to,
            "details": self.details,
            "updated_at": self.updated_at,
        }


class TaskManager:
    """Maintains task state for the active investigation session."""

    def __init__(self) -> None:
        self.tasks: List[InvestigationTask] = []
        self._lock = threading.Lock()

    def update_tasks(self, task_items: List[Dict[str, Any]], session_id: str = "default") -> List[Dict[str, Any]]:
        """Replaces or updates the active plan tasks and broadcasts the updated plan."""
        updated: List[InvestigationTask] = []
        with self._lock:
            for idx, item in enumerate(task_items):
                tid = item.get("id") or f"task_{idx + 1}"
                status_raw = item.get("status", "pending")
                try:
                    status_enum = TaskStatus(status_raw)
                except Exception:
                    status_enum = TaskStatus.PENDING

                t = InvestigationTask(
                    task_id=tid,
                    title=item.get("title") or item.get("text") or f"Step {idx + 1}",
                    status=status_enum,
                    assigned_to=item.get("assigned_to", "main_agent"),
                    details=item.get("details", ""),
                    updated_at=datetime.now(timezone.utc).isoformat(),
                )
                updated.append(t)
            self.tasks = updated

        serialized = [t.to_dict() for t in updated]
        event_bus.publish(
            AgentEvent(
                type="plan_updated",
                status="updated",
                message=f"Plan updated: {len(updated)} step(s)",
                session_id=session_id,
                source="task_manager",
                data={"tasks": serialized},
            )
        )
        return serialized

    def get_tasks(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [t.to_dict() for t in self.tasks]

    def clear(self) -> None:
        with self._lock:
            self.tasks.clear()
