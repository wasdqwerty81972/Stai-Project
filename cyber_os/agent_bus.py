"""
CyberOS Agent Event Bus
Decouples agent actions from UI rendering via typed events
"""

import time
import uuid
import threading
from queue import Queue
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum


class EventType(Enum):
    AGENT_THINKING = "agent.thinking"
    TOOL_STARTED = "tool.started"
    TOOL_PROGRESS = "tool.progress"
    TOOL_COMPLETED = "tool.completed"
    TOOL_FAILED = "tool.failed"
    FINDING_CREATED = "finding.created"
    AGENT_DELEGATED = "agent.delegated"
    WORKFLOW_STARTED = "workflow.started"
    WORKFLOW_COMPLETED = "workflow.completed"
    AGENT_MESSAGE = "agent.message"
    USER_MESSAGE = "user.message"
    ERROR = "error"
    STATUS_CHANGED = "status.changed"
    INVESTIGATION_CREATED = "investigation.created"
    MITRE_MAPPED = "mitre.mapped"
    REMEDIATION_PROPOSED = "remediation.proposed"


@dataclass
class AgentEvent:
    type: str
    timestamp: str
    session_id: str
    tool: Optional[str] = None
    agent: Optional[str] = None
    status: str = "pending"
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "tool": self.tool,
            "agent": self.agent,
            "status": self.status,
            "message": self.message,
            "data": self.data,
        }

    @classmethod
    def create(cls, event_type: EventType, session_id: str, **kwargs) -> "AgentEvent":
        return cls(
            type=event_type.value,
            timestamp=datetime.now().isoformat(),
            session_id=session_id,
            **kwargs,
        )


class AgentEventBus:
    """Thread-safe event bus for agent-to-UI communication."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._queue: Queue = Queue()
        self._listeners: Dict[str, List[Callable]] = {}
        self._history: List[AgentEvent] = []
        self._lock = threading.RLock()
        self._running = False
        self._worker_thread = None

    def start(self):
        """Start the event processing loop."""
        self._running = True
        self._worker_thread = threading.Thread(target=self._process_loop, daemon=True)
        self._worker_thread.start()

    def stop(self):
        """Stop the event processing loop."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=1)

    def emit(self, event: AgentEvent):
        """Emit an event to the bus."""
        with self._lock:
            self._history.append(event)
            if len(self._history) > 1000:
                self._history = self._history[-1000:]
        self._queue.put(event)

    def on(self, event_type: str, callback: Callable[[AgentEvent], None]):
        """Register a callback for an event type."""
        if event_type not in self._listeners:
            self._listeners[event_type] = []
        self._listeners[event_type].append(callback)

    def off(self, event_type: str, callback: Callable[[AgentEvent], None]):
        """Unregister a callback."""
        if event_type in self._listeners:
            self._listeners[event_type] = [cb for cb in self._listeners[event_type] if cb != callback]

    def get_history(self, event_type: Optional[str] = None, limit: int = 100) -> List[AgentEvent]:
        """Get event history, optionally filtered by type."""
        with self._lock:
            events = self._history
            if event_type:
                events = [e for e in events if e.type == event_type]
            return events[-limit:]

    def _process_loop(self):
        """Process events from the queue."""
        while self._running:
            try:
                event = self._queue.get(timeout=0.1)
                self._dispatch(event)
            except Exception:
                continue

    def _dispatch(self, event: AgentEvent):
        """Dispatch event to registered listeners."""
        # Dispatch to specific type listeners
        callbacks = self._listeners.get(event.type, [])
        for callback in callbacks:
            try:
                callback(event)
            except Exception:
                pass

        # Dispatch to wildcard listeners
        wildcards = self._listeners.get("*", [])
        for callback in wildcards:
            try:
                callback(event)
            except Exception:
                pass


class Session:
    """Represents an investigation session."""

    def __init__(self, session_id: str, title: str = "Untitled Session"):
        self.session_id = session_id
        self.title = title
        self.created_at = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()
        self.messages: List[Dict] = []
        self.events: List[Dict] = []
        self.findings: List[Dict] = []
        self.metadata: Dict[str, Any] = {}

    def add_message(self, role: str, content: str):
        """Add a message to the session."""
        message = {
            "role": role,
            "content": content,
            "timestamp": datetime.now().isoformat(),
        }
        self.messages.append(message)
        self.updated_at = message["timestamp"]

    def add_event(self, event: AgentEvent):
        """Add an event to the session."""
        self.events.append(event.to_dict())
        self.updated_at = event.timestamp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "title": self.title,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "messages": self.messages,
            "events": self.events,
            "findings": self.findings,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        session = cls(data["session_id"], data.get("title", "Untitled Session"))
        session.created_at = data.get("created_at", session.created_at)
        session.updated_at = data.get("updated_at", session.updated_at)
        session.messages = data.get("messages", [])
        session.events = data.get("events", [])
        session.findings = data.get("findings", [])
        session.metadata = data.get("metadata", {})
        return session


class SessionManager:
    """Manages investigation sessions."""

    def __init__(self, storage_path: str = ".sessions"):
        self.storage_path = storage_path
        self.sessions: Dict[str, Session] = {}
        self._lock = threading.RLock()
        self._load_sessions()

    def create_session(self, title: str = "Untitled Session") -> Session:
        """Create a new session."""
        session_id = f"session-{datetime.now().strftime('%Y-%m-%d')}-{uuid.uuid4().hex[:8]}"
        session = Session(session_id, title)
        with self._lock:
            self.sessions[session_id] = session
        self._save_session(session)
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        return self.sessions.get(session_id)

    def get_all_sessions(self) -> List[Session]:
        """Get all sessions, sorted by updated_at."""
        with self._lock:
            return sorted(self.sessions.values(), key=lambda s: s.updated_at, reverse=True)

    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        with self._lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                return True
        return False

    def _save_session(self, session: Session):
        """Save session to disk."""
        import os
        import json
        session_dir = os.path.join(self.storage_path, session.session_id)
        os.makedirs(session_dir, exist_ok=True)
        with open(os.path.join(session_dir, "session.json"), "w") as f:
            json.dump(session.to_dict(), f, indent=2)

    def _load_sessions(self):
        """Load all sessions from disk."""
        import os
        import json
        if not os.path.exists(self.storage_path):
            return
        for session_id in os.listdir(self.storage_path):
            session_file = os.path.join(self.storage_path, session_id, "session.json")
            if os.path.exists(session_file):
                try:
                    with open(session_file, "r") as f:
                        data = json.load(f)
                    session = Session.from_dict(data)
                    with self._lock:
                        self.sessions[session_id] = session
                except Exception:
                    pass
