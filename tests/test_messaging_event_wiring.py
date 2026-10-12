"""Pin the production event-bus -> communications-notification wiring.

The live link is established in ``ui/api_server.py`` startup::

    _communications_event_listener = manager.enqueue_event
    event_bus.subscribe_all(_communications_event_listener)

and every agent event is delivered to that listener by ``AgentEventBus.publish``,
which calls each global listener **synchronously** as ``cb(event)``.

The offline service tests (``test_messaging_service.py``) call
``manager.enqueue_event(...)`` *directly*, so nothing currently asserts that an
event actually *published to the bus* reaches the notification queue. That leaves
a silent-failure gap: if ``enqueue_event`` were ever made ``async`` or renamed,
the synchronous bus would create-and-drop a coroutine (the exact footgun behind
the ``_broadcast was never awaited`` warning) and deliver nothing — with no test
failing. These tests close that gap. Fully offline: no secrets, no sockets, no
platform SDKs; a fresh ``AgentEventBus`` instance exercises the same mechanism as
the module-global bus without polluting it across tests.
"""

from __future__ import annotations

import asyncio
import inspect

from stai_messaging.contracts import InboundMessage
from stai_messaging.service import AdapterManager
from ui.event_bus import AgentEvent, AgentEventBus


class _FakeAdapter:
    """Records outbound replies instead of touching a real platform."""

    def __init__(self) -> None:
        self.sent: list = []

    async def send_message(self, reply) -> None:
        self.sent.append(reply)


class _FakeChatClient:
    def chat(self, message: str, session_id: str) -> str:  # pragma: no cover - unused
        return "unused"


def _pair_viewer(manager: AdapterManager) -> str:
    """Approve a viewer pairing and return its destination key."""
    inbound = InboundMessage(
        channel="telegram", account_id="default", sender_id="user-9",
        destination_id="chat-9", message_id="pair-9", text="/pair",
    )
    request_id = manager.identities.request_pairing(inbound)
    manager.identities.approve_pairing(request_id, role="viewer")
    return manager.paired_destinations()[0]["key"]


def test_published_agent_event_reaches_a_paired_destination(tmp_path) -> None:
    """A real subscribe_all(enqueue_event) + bus.publish round-trips to delivery.

    This is the end-to-end production path the direct-``enqueue_event`` service
    tests skip: publish on the bus -> synchronous listener dispatch ->
    notification worker -> adapter send. Also re-asserts the content-free alert
    property on this path (no raw event detail leaks to an external platform).
    """
    async def scenario() -> None:
        bus = AgentEventBus()
        manager = AdapterManager(_FakeChatClient(), tmp_path)
        key = _pair_viewer(manager)
        adapter = _FakeAdapter()
        await manager.start()
        manager._adapters[("telegram", "default")] = adapter
        manager.configure_notifications({
            "enabled": True,
            "event_types": ["incident_created"],
            "destinations": [key],
        })

        # The exact linkage ui/api_server.py establishes at startup.
        bus.subscribe_all(manager.enqueue_event)
        bus.publish(AgentEvent(
            type="incident_created", event_id="wired-1",
            message="raw sensitive hostname detail",
        ))

        await asyncio.sleep(0)
        await manager._queue.join()

        assert len(adapter.sent) == 1, "published event never reached the adapter"
        assert adapter.sent[0].thread_id == "chat-9"
        # Alerts are deliberately content-free; raw detail must never leave the host.
        assert "raw sensitive hostname detail" not in adapter.sent[0].text
        assert manager.delivery_history()[0]["status"] == "delivered"
        await manager.stop()

    asyncio.run(scenario())


def test_enqueue_event_is_a_plain_sync_callable_for_the_bus(tmp_path) -> None:
    """Guard the silent-coroutine regression class directly.

    ``AgentEventBus.publish`` invokes global listeners synchronously (``cb(event)``)
    and swallows exceptions. If ``enqueue_event`` were a coroutine function, the bus
    would build a coroutine and discard it unawaited — delivering nothing, silently.
    A pre-startup publish (no loop/queue yet) must also be a safe no-op, never
    raising, so it cannot take down the bus's synchronous dispatch for every other
    listener.
    """
    manager = AdapterManager(_FakeChatClient(), tmp_path)
    assert not inspect.iscoroutinefunction(manager.enqueue_event)
    # No start() called: loop and queue are None. Must return quietly, not raise.
    manager.enqueue_event(AgentEvent(type="incident_created", event_id="pre-start"))
