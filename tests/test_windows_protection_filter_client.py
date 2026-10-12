"""Offline tests for the STAI minifilter user-mode client (no real driver).

These exercise the real ``FilterClient`` logic through an injected in-memory
native stand-in, with emphasis on the fail-open contract: a timeout, a
disconnected/unavailable port, or a malformed frame must never produce a block.
"""

from __future__ import annotations

from typing import List, Optional

import pytest

from cyber_os.protection.filter_client import (
    FilterClient,
    NativeFilterClient,
    create_filter_client,
    fail_open_verdict,
)
from cyber_os.protection.filter_protocol import (
    FilterCompletion,
    FilterReply,
    FilterRequest,
    decode_filter_reply,
    encode_filter_reply,
    encode_filter_request,
)
from cyber_os.protection.models import ScanVerdict


class _FakeNative(NativeFilterClient):
    """In-memory native stand-in to drive the real FilterClient deterministically."""

    def __init__(self, connect_ok: bool = True, incoming: Optional[List[Optional[bytes]]] = None) -> None:
        self.connect_ok = connect_ok
        self.incoming: List[Optional[bytes]] = list(incoming or [])
        self.sent: List[bytes] = []
        self.closed = False

    def connect(self, port_name: str, timeout_ms: int) -> bool:
        return self.connect_ok

    def receive(self, timeout_ms: int) -> Optional[bytes]:
        if self.incoming:
            return self.incoming.pop(0)
        return None

    def send(self, data: bytes) -> bool:
        self.sent.append(data)
        return True

    def close(self) -> None:
        self.closed = True


class _FakeStore:
    def __init__(self) -> None:
        self.completions: List[tuple] = []

    def record_filter_completion(self, request_id: str, status: str) -> None:
        self.completions.append((request_id, status))


def _block_verdict() -> ScanVerdict:
    return ScanVerdict(
        status="detected",
        action="block",
        rule_id="hash-1",
        rule_version="test-1",
        sha256="a" * 64,
        reason="high-confidence block rule matched",
    )


# --- fail-open verdict -------------------------------------------------------

def test_fail_open_verdict_is_allow_unknown() -> None:
    verdict = fail_open_verdict("timeout")
    assert verdict.action == "allow"
    assert verdict.status == "unknown"


def test_fail_open_verdict_serializes_as_allow_never_block() -> None:
    encoded = encode_filter_reply(FilterReply(request_id=7, verdict=fail_open_verdict()))
    decoded = decode_filter_reply(encoded)
    assert decoded.verdict.action == "allow"
    assert decoded.verdict.action != "block"


# --- receive is fail-safe (never fabricates a request to block) --------------

def test_receive_returns_request_when_frame_valid() -> None:
    frame = encode_filter_request(
        FilterRequest(request_id=5, operation="create", path=r"C:\x.exe")
    )
    client = FilterClient(native_client=_FakeNative(incoming=[frame]))
    assert client.connect()
    request = client.receive()
    assert request is not None
    assert request.request_id == 5
    assert request.operation == "create"


def test_receive_none_on_timeout() -> None:
    client = FilterClient(native_client=_FakeNative(incoming=[]))
    assert client.connect()
    assert client.receive() is None


def test_receive_none_when_disconnected() -> None:
    client = FilterClient(native_client=_FakeNative(connect_ok=False))
    assert client.connect() is False
    assert client.receive() is None


def test_receive_none_on_malformed_frame() -> None:
    client = FilterClient(native_client=_FakeNative(incoming=[b"\xff\xff\xff\xff garbage"]))
    assert client.connect()
    assert client.receive() is None


# --- reply/fail-open never blocks on failure ---------------------------------

def test_reply_is_noop_when_disconnected() -> None:
    native = _FakeNative(connect_ok=False)
    client = FilterClient(native_client=native)
    client.connect()
    client.reply(1, _block_verdict())  # must not raise
    client.reply_fail_open(1)  # must not raise
    assert native.sent == []  # nothing emitted while disconnected


def test_reply_fail_open_sends_allow_verdict() -> None:
    native = _FakeNative()
    client = FilterClient(native_client=native)
    assert client.connect()
    client.reply_fail_open(9, "timeout")
    assert len(native.sent) == 1
    decoded = decode_filter_reply(native.sent[0])
    assert decoded.request_id == 9
    assert decoded.verdict.action == "allow"


# --- blocked count comes only from a confirmed denied completion -------------

def test_block_counted_only_on_completion_not_reply() -> None:
    native = _FakeNative()
    store = _FakeStore()
    client = FilterClient(native_client=native)
    client.set_protection_store(store)
    client.connect()
    # A block *verdict* reply alone must not record a blocked count.
    client.reply(3, _block_verdict())
    assert store.completions == []
    # Only a confirmed denied completion records a blocked outcome.
    client.send_completion(
        FilterCompletion(request_id=3, final_io_status="STATUS_ACCESS_DENIED")
    )
    assert store.completions == [("3", "STATUS_ACCESS_DENIED")]


def test_completion_non_denied_does_not_record_blocked() -> None:
    native = _FakeNative()
    store = _FakeStore()
    client = FilterClient(native_client=native)
    client.set_protection_store(store)
    client.connect()
    client.send_completion(
        FilterCompletion(request_id=4, final_io_status="STATUS_SUCCESS")
    )
    assert store.completions == []


# --- factory stays safe offline ----------------------------------------------

def test_create_filter_client_offline_is_safe() -> None:
    client = create_filter_client(native_client=_FakeNative(connect_ok=False))
    client.connect()  # cannot connect without a driver; must not raise
    assert client.receive() is None  # no phantom request to block
