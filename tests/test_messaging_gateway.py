"""Security and routing tests for the asynchronous communications gateway."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from stai_messaging.contracts import InboundMessage, OutboundReply
from stai_messaging.gateway import Gateway, IdentityStore, session_id_for
from stai_messaging.formatting import split_text


class FakeChatClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def chat(self, message: str, session_id: str) -> str:
        self.calls.append((message, session_id))
        return "response"


class FakeAdapter:
    channel_name = "telegram"

    def __init__(self) -> None:
        self.sent: list[OutboundReply] = []

    async def send_message(self, reply: OutboundReply) -> None:
        self.sent.append(reply)


def message(**changes) -> InboundMessage:
    data = dict(channel="telegram", account_id="bot-1", sender_id="user-7",
                destination_id="chat-1", message_id="message-1", text="status")
    data.update(changes)
    return InboundMessage(**data)


def test_sessions_isolate_sender_account_and_group_conversation() -> None:
    base = message(thread_id="thread-1")
    assert session_id_for(base) != session_id_for(message(sender_id="user-8", thread_id="thread-1"))
    assert session_id_for(base) != session_id_for(message(account_id="bot-2", thread_id="thread-1"))
    assert session_id_for(base) != session_id_for(message(destination_id="chat-2", thread_id="thread-1"))


def test_pairing_requires_approval_and_can_be_revoked(tmp_path) -> None:
    store = IdentityStore(tmp_path / "communications.json")
    request_id = store.request_pairing(message())
    assert store.role_for("telegram", "bot-1", "user-7") is None
    assert store.approve_pairing(request_id, role="analyst")
    assert store.role_for("telegram", "bot-1", "user-7") == "analyst"
    assert store.revoke("telegram", "bot-1", "user-7")
    assert store.role_for("telegram", "bot-1", "user-7") is None


def test_pairing_requests_expire(tmp_path) -> None:
    store = IdentityStore(tmp_path / "communications.json", pairing_ttl=1)
    request_id = store.request_pairing(message(), now=datetime.now(timezone.utc) - timedelta(seconds=5))
    assert not store.approve_pairing(request_id)


def test_gateway_drops_unpaired_and_duplicate_messages(tmp_path) -> None:
    async def scenario() -> None:
        store = IdentityStore(tmp_path / "communications.json")
        client, adapter = FakeChatClient(), FakeAdapter()
        gateway = Gateway(client, store)
        assert await gateway.handle(message(), adapter) is None
        pairing_id = store.request_pairing(message())
        store.approve_pairing(pairing_id, role="analyst")
        reply = await gateway.handle(message(), adapter)
        duplicate = await gateway.handle(message(), adapter)
        assert reply is not None and duplicate is None
        assert len(client.calls) == 1
        assert len(adapter.sent) == 1
    asyncio.run(scenario())


def test_gateway_uses_identity_isolated_session_for_agent(tmp_path) -> None:
    async def scenario() -> None:
        store = IdentityStore(tmp_path / "communications.json")
        client, adapter = FakeChatClient(), FakeAdapter()
        gateway = Gateway(client, store)
        request_id = store.request_pairing(message())
        store.approve_pairing(request_id, role="analyst")
        await gateway.handle(message(thread_id="thread-1"), adapter)
        assert client.calls[0][1] == session_id_for(message(thread_id="thread-1"))
    asyncio.run(scenario())


def test_identity_store_persists_approved_accounts(tmp_path) -> None:
    path = tmp_path / "communications.json"
    store = IdentityStore(path)
    request_id = store.request_pairing(message())
    store.approve_pairing(request_id, role="analyst")
    assert IdentityStore(path).role_for("telegram", "bot-1", "user-7") == "analyst"


def test_viewer_cannot_route_arbitrary_text_to_agent(tmp_path) -> None:
    async def scenario() -> None:
        store = IdentityStore(tmp_path / "communications.json")
        client, adapter = FakeChatClient(), FakeAdapter()
        gateway = Gateway(client, store)
        store.approve_pairing(store.request_pairing(message()))
        await gateway.handle(message(), adapter)
        assert client.calls == []

    asyncio.run(scenario())


def test_attachments_are_rejected_before_agent_dispatch(tmp_path) -> None:
    async def scenario() -> None:
        store = IdentityStore(tmp_path / "communications.json")
        client, adapter = FakeChatClient(), FakeAdapter()
        gateway = Gateway(client, store)
        store.approve_pairing(store.request_pairing(message()), role="analyst")
        await gateway.handle(message(attachments=({"filename": "payload.exe"},)), adapter)
        assert client.calls == []

    asyncio.run(scenario())


def test_split_text_respects_limit_without_losing_characters() -> None:
    text = "alpha beta\n" + ("x" * 80) + " end"
    parts = split_text(text, 20)
    assert all(len(part) <= 20 for part in parts)
    assert "".join(parts) == text


def test_inbound_idempotency_survives_store_restart(tmp_path) -> None:
    path = tmp_path / "communications.json"
    first = IdentityStore(path)
    assert first.claim_message("telegram:bot-1:chat-1:message-1")
    second = IdentityStore(path)
    assert not second.claim_message("telegram:bot-1:chat-1:message-1")


def test_agent_provider_failure_returns_generic_status_to_sender(tmp_path) -> None:
    class FailingClient:
        def chat(self, message: str, session_id: str) -> str:
            raise RuntimeError("secret provider detail")

    async def scenario() -> None:
        store = IdentityStore(tmp_path / "communications.json")
        store.approve_pairing(store.request_pairing(message()), role="analyst")
        adapter = FakeAdapter()
        gateway = Gateway(FailingClient(), store)
        reply = await gateway.handle(message(), adapter)
        assert reply is not None
        assert "could not complete" in reply.text
        assert "secret provider detail" not in reply.text
        assert len(adapter.sent) == 1

    asyncio.run(scenario())


def test_sender_rate_limit_recovers_after_window(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        clock = [100.0]
        monkeypatch.setattr("stai_messaging.gateway.time.monotonic", lambda: clock[0])
        store = IdentityStore(tmp_path / "communications.json")
        store.approve_pairing(store.request_pairing(message()), role="analyst")
        client, adapter = FakeChatClient(), FakeAdapter()
        gateway = Gateway(client, store, messages_per_minute=1)
        assert await gateway.handle(message(message_id="m1"), adapter) is not None
        assert await gateway.handle(message(message_id="m2"), adapter) is None
        clock[0] += 61
        assert await gateway.handle(message(message_id="m3"), adapter) is not None
        assert len(client.calls) == 2

    asyncio.run(scenario())
