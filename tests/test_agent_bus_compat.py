"""Regression tests for the cyber_os.agent_bus compatibility layer.

cyber_os/agent_bus.py was de-duplicated to re-export the canonical bus from
ui.event_bus. The two classes have different APIs: the canonical one takes no
constructor argument and exposes subscribe/publish, while the historical
CyberOS one took a session_id and exposed start/stop/emit/on/off plus a
``limit`` kwarg on get_history.

cyber_os/workspace.py still uses the historical API, so a bare re-export made
it raise TypeError/AttributeError at runtime. Nothing in the suite constructed
the bus, so the breakage was invisible. These tests pin the legacy surface.
"""

import unittest

from cyber_os.agent_bus import AgentEvent, AgentEventBus


class TestAgentBusLegacyAPI(unittest.TestCase):
    """The legacy surface cyber_os/workspace.py depends on must keep working."""

    def test_constructor_accepts_session_id(self):
        """workspace.py:694 calls AgentEventBus(session_id) positionally."""
        bus = AgentEventBus("sess-abc")
        self.assertEqual(bus.session_id, "sess-abc")

    def test_constructor_defaults_without_session_id(self):
        """The canonical no-arg construction must still work."""
        self.assertEqual(AgentEventBus().session_id, "default")

    def test_start_and_stop_are_callable(self):
        """workspace.py:695 calls .start(); the canonical bus has no such method."""
        bus = AgentEventBus("sess-abc")
        bus.start()
        bus.stop()

    def test_emit_records_event_in_history(self):
        """workspace.py:915 calls .emit(); the canonical bus only has .publish()."""
        bus = AgentEventBus("sess-abc")
        bus.emit(AgentEvent(type="tool.started", message="scan"))
        history = bus.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].type, "tool.started")

    def test_emit_stamps_bus_session_id(self):
        """An event with no session must inherit the bus's session, not 'default'."""
        bus = AgentEventBus("sess-abc")
        bus.emit(AgentEvent(type="tool.completed"))
        self.assertEqual(bus.get_history()[0].session_id, "sess-abc")

    def test_emit_preserves_explicit_session_id(self):
        """An explicitly-set session id must not be overwritten by the bus."""
        bus = AgentEventBus("sess-abc")
        bus.emit(AgentEvent(type="error", session_id="explicit-999"))
        self.assertEqual(bus.get_history()[0].session_id, "explicit-999")

    def test_get_history_limit_returns_most_recent(self):
        """workspace.py:967 calls get_history(limit=10); canonical has no limit."""
        bus = AgentEventBus("sess-abc")
        for i in range(5):
            bus.emit(AgentEvent(type="tool.progress", message=str(i)))
        recent = bus.get_history(limit=2)
        self.assertEqual([e.message for e in recent], ["3", "4"])

    def test_get_history_limit_larger_than_history(self):
        """A limit above the event count must not pad or error."""
        bus = AgentEventBus("sess-abc")
        bus.emit(AgentEvent(type="tool.progress"))
        self.assertEqual(len(bus.get_history(limit=1000)), 1)

    def test_get_history_without_limit_returns_all(self):
        bus = AgentEventBus("sess-abc")
        for _ in range(3):
            bus.emit(AgentEvent(type="tool.progress"))
        self.assertEqual(len(bus.get_history()), 3)

    def test_get_history_filters_by_event_type(self):
        """The canonical event_type filter must survive the override."""
        bus = AgentEventBus("sess-abc")
        bus.emit(AgentEvent(type="tool.started"))
        bus.emit(AgentEvent(type="error"))
        self.assertEqual(len(bus.get_history("error")), 1)

    def test_on_and_off_manage_subscriptions(self):
        """Legacy on/off aliases must route to subscribe/unsubscribe."""
        bus = AgentEventBus("sess-abc")
        received = []
        bus.on("tool.started", received.append)
        bus.emit(AgentEvent(type="tool.started"))
        self.assertEqual(len(received), 1)

        bus.off("tool.started", received.append)
        bus.emit(AgentEvent(type="tool.started"))
        self.assertEqual(len(received), 1, "unsubscribed callback still fired")

    def test_workspace_call_sequence(self):
        """End-to-end mirror of cyber_os/workspace.py's actual usage."""
        bus = AgentEventBus("sess-workspace")
        bus.start()
        bus.emit(
            AgentEvent(
                type="tool.started",
                session_id=bus.session_id,
                tool="nmap",
                status="running",
            )
        )
        self.assertEqual(len(bus.get_history(limit=10)), 1)
        self.assertEqual(len(bus.get_history(limit=1000)), 1)


if __name__ == "__main__":
    unittest.main()
