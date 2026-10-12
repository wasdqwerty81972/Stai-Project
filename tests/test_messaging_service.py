"""Service-level notification routing tests with no platform APIs."""

from __future__ import annotations

import asyncio

from stai_messaging.contracts import InboundMessage
from stai_messaging.gateway import IdentityStore
from stai_messaging.service import AdapterManager
from ui.event_bus import AgentEvent


class FakeAdapter:
    def __init__(self, fail_count: int = 0) -> None:
        self.fail_count = fail_count
        self.sent = []

    async def send_message(self, reply) -> None:
        if self.fail_count:
            self.fail_count -= 1
            raise RuntimeError("mock platform outage")
        self.sent.append(reply)


class FakeChatClient:
    def chat(self, message: str, session_id: str) -> str:
        return "unused"


def paired_manager(tmp_path):
    manager = AdapterManager(FakeChatClient(), tmp_path)
    inbound = InboundMessage(
        channel="telegram", account_id="default", sender_id="user-4",
        destination_id="private-chat-4", message_id="pair-1", text="/pair",
    )
    request_id = manager.identities.request_pairing(inbound)
    manager.identities.approve_pairing(request_id, role="viewer")
    return manager


def test_security_event_notifies_only_selected_paired_destinations(tmp_path) -> None:
    async def scenario() -> None:
        manager = paired_manager(tmp_path)
        adapter = FakeAdapter()
        await manager.start()
        manager._adapters[("telegram", "default")] = adapter
        identity_key = manager.paired_destinations()[0]["key"]
        manager.configure_notifications({
            "enabled": True,
            "event_types": ["incident_created"],
            "destinations": [identity_key],
        })
        event = AgentEvent(type="incident_created", event_id="incident-1", message="secret hostname and finding")
        manager.enqueue_event(event)
        manager.enqueue_event(event)
        await asyncio.sleep(0)
        await manager._queue.join()
        assert len(adapter.sent) == 1
        assert "secret hostname" not in adapter.sent[0].text
        assert adapter.sent[0].thread_id == "private-chat-4"
        assert manager.delivery_history()[0]["status"] == "delivered"
        await manager.stop()
    asyncio.run(scenario())


def test_notification_retries_transient_delivery_errors(tmp_path) -> None:
    async def scenario() -> None:
        manager = paired_manager(tmp_path)
        adapter = FakeAdapter(fail_count=2)
        await manager.start()
        manager._adapters[("telegram", "default")] = adapter
        identity_key = manager.paired_destinations()[0]["key"]
        manager.configure_notifications({
            "enabled": True,
            "event_types": ["finding_created"],
            "destinations": [identity_key],
        })
        manager.enqueue_event(AgentEvent(type="finding_created", event_id="finding-1"))
        await asyncio.sleep(0)
        await manager._queue.join()
        assert len(adapter.sent) == 1
        assert manager.delivery_history()[0]["status"] == "delivered"
        await manager.stop()
    asyncio.run(scenario())


def test_notifications_reject_unpaired_destinations(tmp_path) -> None:
    manager = AdapterManager(FakeChatClient(), tmp_path)
    try:
        manager.configure_notifications({
            "enabled": True,
            "event_types": ["incident_created"],
            "destinations": ["telegram:default:unknown"],
        })
    except ValueError as exc:
        assert "paired" in str(exc)
    else:
        raise AssertionError("an unpaired recipient must not be accepted")


def test_offline_delivery_is_persisted_and_retried_after_restart(tmp_path) -> None:
    async def scenario() -> None:
        manager = paired_manager(tmp_path)
        identity_key = manager.paired_destinations()[0]["key"]
        await manager.start()
        manager.configure_notifications({
            "enabled": True,
            "event_types": ["incident_created"],
            "destinations": [identity_key],
        })
        event = AgentEvent(type="incident_created", event_id="durable-event")
        manager.enqueue_event(event)
        await asyncio.sleep(0)
        await manager._queue.join()
        assert manager.delivery_history()[0]["status"] == "offline"
        await manager.stop()

        restarted = AdapterManager(FakeChatClient(), tmp_path)
        adapter = FakeAdapter()
        await restarted.start()
        restarted._adapters[("telegram", "default")] = adapter
        restarted._requeue_pending()
        await asyncio.sleep(0)
        await restarted._queue.join()
        restarted.enqueue_event(event)
        await asyncio.sleep(0)
        await restarted._queue.join()
        assert len(adapter.sent) == 1
        assert restarted.delivery_history()[0]["status"] == "delivered"
        await restarted.stop()
    asyncio.run(scenario())
