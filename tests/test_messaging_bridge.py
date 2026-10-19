"""Offline unit tests for the messaging-bridge seam (Idea #10, Phase 1).

No network, no credentials: a fake ChatClient stands in for the STAI agent and a
MockChannelAdapter captures replies.
"""

from __future__ import annotations

import dataclasses

import pytest

from stai_messaging import (
    ALLOW_ALL,
    AllowList,
    InboundMessage,
    MessageBridge,
    OutboundReply,
    session_id_for,
)
from stai_messaging.adapters.mock import MockChannelAdapter


class FakeChatClient:
    """Records calls and returns a canned, deterministic reply."""

    def __init__(self, reply: str = "ack") -> None:
        self.reply = reply
        self.calls: list[tuple[str, str]] = []

    def chat(self, message: str, session_id: str) -> str:
        self.calls.append((message, session_id))
        return self.reply


def _msg(**kw) -> InboundMessage:
    base = {"channel": "discord", "sender_id": "user1", "text": "hello"}
    base.update(kw)
    return InboundMessage(**base)


# --- contracts ---------------------------------------------------------------
def test_inbound_message_requires_channel_and_sender():
    with pytest.raises(ValueError):
        InboundMessage(channel="", sender_id="u", text="x")
    with pytest.raises(ValueError):
        InboundMessage(channel="discord", sender_id="", text="x")


def test_inbound_message_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        _msg().text = "changed"  # type: ignore[misc]


# --- allow-list: default deny ------------------------------------------------
def test_empty_allow_list_denies_everyone():
    al = AllowList()
    assert al.is_allowed("discord", "user1") is False
    assert al.is_allowed("telegram", "anyone") is False


def test_unknown_channel_is_denied():
    al = AllowList({"discord": ["user1"]})
    assert al.is_allowed("telegram", "user1") is False


def test_unknown_sender_is_denied():
    al = AllowList({"discord": ["user1"]})
    assert al.is_allowed("discord", "user2") is False


def test_listed_sender_is_allowed():
    al = AllowList({"discord": ["user1", "user2"]})
    assert al.is_allowed("discord", "user1") is True
    assert al.is_allowed("discord", "user2") is True


def test_wildcard_allows_any_sender_but_only_on_that_channel():
    al = AllowList({"discord": [ALLOW_ALL]})
    assert al.is_allowed("discord", "whoever") is True
    assert al.is_allowed("telegram", "whoever") is False


def test_bare_string_sender_is_treated_as_one_id_not_characters():
    # A natural single-user misconfig: a bare string instead of a list. It must
    # mean "allow exactly this sender" -- never expand to its characters, which
    # would both deny the real sender and allow any single-char id on the channel.
    al = AllowList({"discord": "myuserid"})
    assert al.is_allowed("discord", "myuserid") is True
    assert al.is_allowed("discord", "m") is False
    assert al.is_allowed("discord", "myuse") is False


def test_list_form_allow_list_is_unaffected_by_the_bare_string_guard():
    al = AllowList({"discord": ["user1", "user2"]})
    assert al.is_allowed("discord", "user1") is True
    assert al.is_allowed("discord", "user2") is True
    assert al.is_allowed("discord", "u") is False


# --- session mapping ---------------------------------------------------------
def test_session_id_uses_thread_when_present():
    assert session_id_for(_msg(thread_id="chan-42")) == "discord:chan-42"


def test_session_id_falls_back_to_sender():
    assert session_id_for(_msg(sender_id="user9")) == "discord:user9"


def test_session_id_falls_back_to_sender_when_thread_is_empty_string():
    # thread_id="" is falsy, so an empty thread maps to the per-sender session
    # rather than a shared, collision-prone "channel:" bucket.
    assert session_id_for(_msg(sender_id="u7", thread_id="")) == "discord:u7"


def test_session_id_is_stable_per_thread_across_messages():
    a = session_id_for(_msg(thread_id="t1", message_id="m1"))
    b = session_id_for(_msg(thread_id="t1", message_id="m2"))
    assert a == b


# --- bridge round-trip -------------------------------------------------------
def test_allowed_message_reaches_agent_and_reply_is_relayed():
    client = FakeChatClient(reply="investigation started")
    adapter = MockChannelAdapter("discord")
    bridge = MessageBridge(client, AllowList({"discord": ["user1"]}))

    out = bridge.handle(
        _msg(text="scan 10.0.0.1", message_id="m1", thread_id="t1"), adapter
    )

    assert client.calls == [("scan 10.0.0.1", "discord:t1")]
    assert adapter.sent == [
        OutboundReply("discord", "t1", "investigation started", "m1")
    ]
    assert out == adapter.sent[0]


def test_denied_message_never_reaches_agent_or_adapter():
    client = FakeChatClient()
    adapter = MockChannelAdapter("discord")
    bridge = MessageBridge(client, AllowList({"discord": ["user1"]}))

    out = bridge.handle(_msg(sender_id="intruder"), adapter)

    assert out is None
    assert client.calls == []
    assert adapter.sent == []


def test_denied_message_on_unlisted_channel_is_dropped():
    client = FakeChatClient()
    adapter = MockChannelAdapter("telegram")
    bridge = MessageBridge(client, AllowList({"discord": [ALLOW_ALL]}))

    out = bridge.handle(InboundMessage("telegram", "anyone", "hi"), adapter)

    assert out is None
    assert client.calls == []
    assert adapter.sent == []


def test_bridge_relays_multiple_replies_and_keeps_sessions_separate():
    client = FakeChatClient(reply="ok")
    adapter = MockChannelAdapter("telegram")
    bridge = MessageBridge(client, AllowList({"telegram": [ALLOW_ALL]}))

    bridge.handle(InboundMessage("telegram", "a", "one"), adapter)
    bridge.handle(InboundMessage("telegram", "b", "two"), adapter)

    assert [c[0] for c in client.calls] == ["one", "two"]
    assert client.calls[0][1] == "telegram:a"
    assert client.calls[1][1] == "telegram:b"
    assert [r.text for r in adapter.sent] == ["ok", "ok"]


# --- mock adapter contract ---------------------------------------------------
def test_mock_adapter_exposes_channel_name_and_records():
    adapter = MockChannelAdapter("sms")
    assert adapter.channel_name == "sms"
    assert adapter.sent == []
    adapter.send(OutboundReply("sms", None, "hi"))
    assert len(adapter.sent) == 1
