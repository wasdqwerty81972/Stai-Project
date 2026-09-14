"""
Agent Event Bus

Provides a decoupled event system for the UI to consume agent activities.
All UI updates should be driven by events from this bus.
"""
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional


@dataclass
class AgentEvent:
    type: str
    timestamp: str = ""
    session_id: str = ""
    event_id: str = ""
    investigation_id: str = ""
    source: str = "agent"
    correlation_id: str = ""
    entity_ids: List[str] = field(default_factory=list)
    tool: Optional[str] = None
    agent: Optional[str] = None
    status: str = ""
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
        if not self.session_id:
            self.session_id = "default"
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        if not self.correlation_id:
            self.correlation_id = self.event_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "event_id": self.event_id,
            "investigation_id": self.investigation_id,
            "source": self.source,
            "correlation_id": self.correlation_id,
            "entity_ids": list(self.entity_ids),
            "tool": self.tool,
            "agent": self.agent,
            "status": self.status,
            "message": self.message,
            "data": self.data,
        }


class AgentEventBus:
    """Thread-safe event bus for agent-to-UI communication."""

    def __init__(self):
        self._listeners: Dict[str, List[Callable[[AgentEvent], None]]] = {}
        self._global_listeners: List[Callable[[AgentEvent], None]] = []
        self._lock = threading.Lock()
        self._history: List[AgentEvent] = []
        self._session_context = threading.local()

    @contextmanager
    def session_scope(self, session_id: str):
        previous = getattr(self._session_context, "session_id", None)
        self._session_context.session_id = session_id
        try:
            yield
        finally:
            if previous is None:
                try:
                    del self._session_context.session_id
                except AttributeError:
                    pass
            else:
                self._session_context.session_id = previous

    def subscribe(self, event_type: str, callback: Callable[[AgentEvent], None]):
        with self._lock:
            if event_type not in self._listeners:
                self._listeners[event_type] = []
            self._listeners[event_type].append(callback)

    def unsubscribe(self, event_type: str, callback: Callable[[AgentEvent], None]):
        with self._lock:
            if event_type in self._listeners:
                self._listeners[event_type] = [
                    cb for cb in self._listeners[event_type] if cb != callback
                ]

    def subscribe_all(self, callback: Callable[[AgentEvent], None]):
        with self._lock:
            self._global_listeners.append(callback)

    def publish(self, event: AgentEvent):
        scoped_session = getattr(self._session_context, "session_id", None)
        if scoped_session and (not event.session_id or event.session_id == "default"):
            event.session_id = scoped_session
        with self._lock:
            self._history.append(event)
            if len(self._history) > 1000:
                self._history = self._history[-500:]
            listeners = list(self._listeners.get(event.type, []))
            global_listeners = list(self._global_listeners)

        for cb in listeners:
            try:
                cb(event)
            except Exception:
                pass
        for cb in global_listeners:
            try:
                cb(event)
            except Exception:
                pass

    def get_history(self, event_type: Optional[str] = None) -> List[AgentEvent]:
        with self._lock:
            if event_type is None:
                return list(self._history)
            return [e for e in self._history if e.type == event_type]


# Global event bus instance
event_bus = AgentEventBus()
