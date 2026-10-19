"""
cyber_os/notes_manager.py — Investigation Notes & Evidence Scratchpad for SVS-Cyber

Provides persistent investigation notes, hypothesis tracking, and evidence scratchpad.
Adapted from mature agent note-taking architecture for SVS-Cyber.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ui.event_bus import AgentEvent, event_bus


@dataclass
class InvestigationNote:
    note_id: str
    title: str
    content: str
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.note_id,
            "title": self.title,
            "content": self.content,
            "tags": self.tags,
            "created_at": self.created_at,
        }


class NotesManager:
    """Maintains notes for active and historical investigations."""

    def __init__(self) -> None:
        self.notes: Dict[str, InvestigationNote] = {}
        self._lock = threading.Lock()

    def create_note(
        self,
        title: str,
        content: str,
        tags: Optional[List[str]] = None,
        session_id: str = "default",
    ) -> Dict[str, Any]:
        note_id = f"note_{uuid.uuid4().hex[:8]}"
        note = InvestigationNote(
            note_id=note_id,
            title=title,
            content=content,
            tags=tags or ["evidence"],
        )
        with self._lock:
            self.notes[note_id] = note

        serialized = note.to_dict()
        event_bus.publish(
            AgentEvent(
                type="note_created",
                status="created",
                message=f"Note created: {title}",
                session_id=session_id,
                source="notes_manager",
                data=serialized,
            )
        )
        return serialized

    def list_notes(self, tag: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            notes = list(self.notes.values())
            if tag:
                notes = [n for n in notes if tag in n.tags]
            return [n.to_dict() for n in notes]

    def delete_note(self, note_id: str) -> bool:
        with self._lock:
            return self.notes.pop(note_id, None) is not None
