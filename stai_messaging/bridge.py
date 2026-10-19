"""The messaging-bridge seam: allow-list + session mapping + relay (Idea #10, Phase 1).

This is the single chokepoint every channel adapter funnels through, so the
default-deny boundary and the thread->session mapping live in exactly one place.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Optional, Sequence

from .contracts import ChannelAdapter, ChatClient, InboundMessage, OutboundReply

# Explicit opt-in wildcard: an allow-list entry of ["*"] allows any sender on that
# channel. Absent by default — an empty allow-list denies everyone.
ALLOW_ALL = "*"


class AllowList:
    """Default-deny sender allow-list, keyed by channel.

    A sender is allowed only if its channel has an entry AND the sender id is in
    that entry's set — or the entry contains the explicit ``*`` (ALLOW_ALL)
    wildcard, which opts the whole channel in. An empty allow-list denies everyone.
    """

    def __init__(self, allowed: Optional[Dict[str, Sequence[str]]] = None) -> None:
        # A bare ``str`` is itself a ``Sequence[str]``, so ``frozenset("myid")``
        # would silently expand to {'m','y','i','d'} — denying the intended
        # sender *and* allowing any single-character id on that channel. Coerce a
        # lone string to one id so the natural single-user config
        # ({"discord": "myid"}) means exactly what it says. (This is a security
        # boundary; a quiet misconfig here is a quiet hole.)
        self._allowed: Dict[str, FrozenSet[str]] = {
            channel: frozenset([ids] if isinstance(ids, str) else ids)
            for channel, ids in (allowed or {}).items()
        }

    def is_allowed(self, channel: str, sender_id: str) -> bool:
        ids = self._allowed.get(channel)
        if not ids:
            return False
        return ALLOW_ALL in ids or sender_id in ids


def session_id_for(inbound: InboundMessage) -> str:
    """Map a chat thread to a stable STAI session id.

    Each (channel, thread) gets its own agent session so conversations don't bleed
    across people or channels; falls back to the sender when there is no thread.
    """
    scope = inbound.thread_id or inbound.sender_id
    return f"{inbound.channel}:{scope}"


class MessageBridge:
    """Routes an allowed inbound message through the STAI agent and relays the reply.

    Denied messages are dropped silently (``handle`` returns ``None``) and the agent
    is never invoked — the default-deny guarantee the Phase 1 tests pin.
    """

    def __init__(self, chat_client: ChatClient, allow_list: AllowList) -> None:
        self._chat_client = chat_client
        self._allow_list = allow_list

    def handle(
        self, inbound: InboundMessage, adapter: ChannelAdapter
    ) -> Optional[OutboundReply]:
        if not self._allow_list.is_allowed(inbound.channel, inbound.sender_id):
            return None  # default-deny: drop, never reach the agent
        session_id = session_id_for(inbound)
        reply_text = self._chat_client.chat(inbound.text, session_id)
        reply = OutboundReply(
            channel=inbound.channel,
            thread_id=inbound.thread_id,
            text=reply_text,
            in_reply_to=inbound.message_id,
        )
        adapter.send(reply)
        return reply
