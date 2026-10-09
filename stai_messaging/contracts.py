"""Provider-agnostic contracts for the STAI messaging bridge (Idea #10, Phase 1).

Intentionally dependency-free (stdlib only) so the bridge seam is cheap to import
and trivial to unit-test offline, before any live channel exists. Live channel
adapters (Discord/Telegram/WhatsApp/SMS) are Phase 2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class InboundMessage:
    """A message received from a chat platform, normalized to a channel-neutral shape.

    ``thread_id`` is the platform conversation/thread (Discord channel id, Telegram
    chat id, ...); ``sender_id`` is who sent it. Both are opaque strings to the bridge.
    """

    channel: str
    sender_id: str
    text: str
    thread_id: Optional[str] = None
    message_id: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.channel:
            raise ValueError("InboundMessage.channel is required")
        if not self.sender_id:
            raise ValueError("InboundMessage.sender_id is required")


@dataclass(frozen=True)
class OutboundReply:
    """A reply to deliver back to the originating chat platform."""

    channel: str
    thread_id: Optional[str]
    text: str
    in_reply_to: Optional[str] = None


@runtime_checkable
class ChatClient(Protocol):
    """Runs one message through the STAI agent and returns its reply text.

    Phase 1 ships ``HttpChatClient`` (POSTs to the running UI's ``/api/chat``);
    tests inject a fake to stay offline.
    """

    def chat(self, message: str, session_id: str) -> str:
        ...


@runtime_checkable
class ChannelAdapter(Protocol):
    """Delivers an outbound reply to a chat platform. One adapter per channel."""

    @property
    def channel_name(self) -> str:
        ...

    def send(self, reply: OutboundReply) -> None:
        ...
