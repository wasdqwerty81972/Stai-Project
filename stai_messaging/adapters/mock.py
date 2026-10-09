"""Offline mock adapter — records replies in memory instead of sending them.

Phase 1 only. Lets the bridge seam be exercised end-to-end with no network, no
credentials, and no added attack surface.
"""

from __future__ import annotations

from typing import List

from ..contracts import OutboundReply


class MockChannelAdapter:
    """A ``ChannelAdapter`` that captures outbound replies. No I/O."""

    def __init__(self, channel_name: str = "mock") -> None:
        self._channel_name = channel_name
        self.sent: List[OutboundReply] = []

    @property
    def channel_name(self) -> str:
        return self._channel_name

    def send(self, reply: OutboundReply) -> None:
        self.sent.append(reply)
