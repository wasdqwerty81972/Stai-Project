"""STAI multi-channel messaging bridge (Idea #10, Phase 1 — offline seam).

See ``README.md``. Phase 1 is dependency-free and offline: it defines the
provider-agnostic bridge seam (normalized inbound message, default-deny
allow-list, thread->session mapping, reply relay) plus a mock adapter. Live
channel adapters (Discord/Telegram/WhatsApp/SMS) are Phase 2 and gated on
owner-provided secrets.
"""

from .bridge import ALLOW_ALL, AllowList, MessageBridge, session_id_for
from .contracts import ChannelAdapter, ChatClient, InboundMessage, OutboundReply
from .http_chat_client import DEFAULT_BASE_URL, HttpChatClient

__all__ = [
    "ALLOW_ALL",
    "AllowList",
    "MessageBridge",
    "session_id_for",
    "ChannelAdapter",
    "ChatClient",
    "InboundMessage",
    "OutboundReply",
    "HttpChatClient",
    "DEFAULT_BASE_URL",
]
