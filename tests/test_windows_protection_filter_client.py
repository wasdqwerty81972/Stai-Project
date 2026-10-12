"""Offline tests for the STAI minifilter user-mode client (no real driver).

These exercise the real ``FilterClient`` logic through an injected in-memory
native stand-in, with emphasis on the fail-open contract: a timeout, a
disconnected/unavailable port, or a malformed frame must never produce a block.
"""

from __future__ import annotations

import ctypes
import struct
import threading
from typing import List, Optional

import pytest

import cyber_os.protection.filter_client as filter_client_module
from cyber_os.protection.filter_client import (
    FilterClient,
    NativeFilterMessage,
    NativeFilterClient,
    FilterTransportError,
    WindowsNativeClient,
    _service_scan_path,
    create_filter_client,
    fail_open_verdict,
)
from cyber_os.protection.filter_protocol import (
    FilterCompletion,
    FilterReply,
    FilterRequest,
    decode_filter_reply,
    encode_filter_completion,
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
        self.reply_calls: List[tuple[int, bytes]] = []
        self.closed = False
        self.next_message_id = 1

    def connect(self, port_name: str, timeout_ms: int) -> bool:
        return self.connect_ok

    def receive(self, timeout_ms: int) -> Optional[NativeFilterMessage]:
        if self.incoming:
            data = self.incoming.pop(0)
            if data is None:
                return None
            message_id = self.next_message_id
            self.next_message_id += 1
            # Completion frames are notifications from the driver and need
            # no FilterReplyMessage response.
            reply_length = 0 if len(data) == 20 else 4096
            return NativeFilterMessage(message_id, data, reply_length)
        return None

    def send(self, data: bytes) -> bool:
        self.sent.append(data)
        return True

    def reply(self, message_id: int, data: bytes) -> bool:
        self.reply_calls.append((message_id, data))
        return True

    def close(self) -> None:
        self.closed = True


class _FakeStore:
    def __init__(self) -> None:
        self.completions: List[tuple] = []
        self.completion_event = threading.Event()

    def record_filter_completion(self, request_id: str, status: str) -> None:
        self.completions.append((request_id, status))
        self.completion_event.set()


class _PendingReceiveNative(_FakeNative):
    """Fake port that exposes whether an overlapped receive is pending."""

    def __init__(self, request_frame: bytes, completion_frame: bytes):
        super().__init__(incoming=[request_frame])
        self._condition = threading.Condition()
        self._completion_frame = completion_frame
        self.pending_receivers = 0
        self.pending_event = threading.Event()
        self.pending_at_reply = False

    def receive(self, timeout_ms: int) -> Optional[NativeFilterMessage]:
        with self._condition:
            if not self.incoming:
                self.pending_receivers += 1
                self.pending_event.set()
                self._condition.wait(timeout_ms / 1000)
                self.pending_receivers -= 1
            if not self.incoming:
                return None
            data = self.incoming.pop(0)
            message_id = self.next_message_id
            self.next_message_id += 1
            reply_length = 0 if len(data) == 20 else 4096
            return NativeFilterMessage(message_id, data, reply_length)

    def reply(self, message_id: int, data: bytes) -> bool:
        with self._condition:
            self.pending_at_reply = self.pending_receivers > 0
            self.reply_calls.append((message_id, data))
            self.incoming.append(self._completion_frame)
            self._condition.notify_all()
            return True


class _FakeFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


class _FakeKernel32:
    def __init__(self, message_size: int):
        self.message_size = message_size
        self.closed_handles: list[int] = []
        self.CreateEventW = _FakeFunction(lambda *_args: 1)
        self.WaitForSingleObject = _FakeFunction(lambda *_args: 0)
        self.GetOverlappedResult = _FakeFunction(self._get_overlapped_result)
        self.CancelIoEx = _FakeFunction(lambda *_args: 1)
        self.CloseHandle = _FakeFunction(self._close_handle)

    def _close_handle(self, handle):
        self.closed_handles.append(int(handle.value if hasattr(handle, "value") else handle))
        return 1

    def _get_overlapped_result(self, _handle, _overlapped, bytes_out, _wait):
        ctypes.cast(bytes_out, ctypes.POINTER(ctypes.c_uint32)).contents.value = self.message_size
        return 1


class _FakeFltLib:
    def __init__(self, incoming: bytes):
        self.incoming = incoming
        self.reply_calls: list[tuple[int, int, bytes]] = []
        self.reply_header_bytes = b""
        self.get_message_arg_count = 0
        self.connect_name = ""
        self.FilterConnectCommunicationPort = _FakeFunction(self._connect)
        self.FilterGetMessage = _FakeFunction(self._get_message)
        self.FilterReplyMessage = _FakeFunction(self._reply_message)

    def _connect(self, name, _options, _context, _context_size, _security, handle_out):
        self.connect_name = name
        ctypes.cast(handle_out, ctypes.POINTER(ctypes.c_void_p)).contents.value = 0x1234
        return 0

    def _get_message(self, _handle, buffer, capacity, overlapped):
        self.get_message_arg_count = 4
        assert capacity >= len(self.incoming)
        ctypes.memmove(buffer, self.incoming, len(self.incoming))
        return 0x800703E5  # HRESULT_FROM_WIN32(ERROR_IO_PENDING)

    def _reply_message(self, _handle, reply_buffer, size):
        self.reply_header_bytes = ctypes.string_at(reply_buffer, 16)
        header = ctypes.cast(
            reply_buffer, ctypes.POINTER(filter_client_module._FILTER_REPLY_HEADER)
        ).contents
        payload = ctypes.string_at(
            ctypes.addressof(reply_buffer.contents) + 16, size - 16
        )
        self.reply_calls.append((int(header.MessageId), size, payload))
        return 0


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
    native = _FakeNative(incoming=[encode_filter_request(
        FilterRequest(request_id=9, operation="create", path=r"C:\x.exe")
    )])
    client = FilterClient(native_client=native)
    assert client.connect()
    assert client.receive() is not None
    client.reply_fail_open(9, "timeout")
    assert len(native.reply_calls) == 1
    _, payload = native.reply_calls[0]
    decoded = decode_filter_reply(payload)
    assert decoded.request_id == 9
    assert decoded.verdict.action == "allow"


def test_reply_uses_filter_reply_message_with_received_os_message_id() -> None:
    frame = encode_filter_request(
        FilterRequest(request_id=5, operation="create", path=r"C:\x.exe")
    )
    native = _FakeNative(incoming=[frame])
    client = FilterClient(native_client=native)
    assert client.connect()
    request = client.receive()
    assert request is not None

    client.reply(request.request_id, _block_verdict())

    assert len(native.reply_calls) == 1
    message_id, payload = native.reply_calls[0]
    assert message_id == 1
    assert decode_filter_reply(payload).request_id == request.request_id


def test_reply_for_different_request_id_cannot_answer_pending_message() -> None:
    frame = encode_filter_request(
        FilterRequest(request_id=5, operation="create", path=r"C:\x.exe")
    )
    native = _FakeNative(incoming=[frame])
    client = FilterClient(native_client=native)
    assert client.connect()
    assert client.receive() is not None

    client.reply(6, _block_verdict())

    assert native.reply_calls == []


def test_driver_completion_message_is_required_to_count_blocked() -> None:
    native = _FakeNative(incoming=[
        encode_filter_completion(
            FilterCompletion(request_id=12, final_io_status="STATUS_ACCESS_DENIED")
        )
    ])
    store = _FakeStore()
    client = FilterClient(native_client=native)
    client.set_protection_store(store)
    assert client.connect()

    assert client.receive() is None

    assert store.completions == [("12", "STATUS_ACCESS_DENIED")]
    assert native.reply_calls == []


def test_process_next_scans_and_replies_to_matching_filter_request() -> None:
    frame = encode_filter_request(
        FilterRequest(request_id=19, operation="image_mapping", path=r"C:\x.exe")
    )
    native = _FakeNative(incoming=[frame])
    client = FilterClient(native_client=native)
    assert client.connect()
    scanned: List[str] = []

    class Service:
        def scan_file(self, path):
            scanned.append(str(path))
            return _block_verdict()

    request = client.process_next(Service())

    assert request is not None and request.request_id == 19
    assert scanned == [r"C:\x.exe"]
    assert len(native.reply_calls) == 1
    _, payload = native.reply_calls[0]
    assert decode_filter_reply(payload).verdict.action == "block"


def test_process_next_scan_error_replies_fail_open() -> None:
    frame = encode_filter_request(
        FilterRequest(request_id=20, operation="create", path=r"C:\x.exe")
    )
    native = _FakeNative(incoming=[frame])
    client = FilterClient(native_client=native)
    assert client.connect()

    class BrokenService:
        def scan_file(self, _path):
            raise OSError("scanner unavailable")

    request = client.process_next(BrokenService())

    assert request is not None and request.request_id == 20
    assert len(native.reply_calls) == 1
    _, payload = native.reply_calls[0]
    decoded = decode_filter_reply(payload)
    assert decoded.request_id == 20
    assert decoded.verdict.action == "allow"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (r"\Device\HarddiskVolume4\Windows\x.exe", r"\\?\GLOBALROOT\Device\HarddiskVolume4\Windows\x.exe"),
        (r"\??\C:\Windows\x.exe", r"\\?\C:\Windows\x.exe"),
        (r"\??\UNC\server\share\x.exe", r"\\?\UNC\server\share\x.exe"),
    ],
)
def test_kernel_nt_path_is_openable_from_windows_service(source: str, expected: str) -> None:
    assert str(_service_scan_path(source, windows=True)) == expected


def test_run_until_stopped_processes_request_then_exits() -> None:
    frame = encode_filter_request(
        FilterRequest(request_id=21, operation="create", path=r"C:\x.exe")
    )
    native = _FakeNative(incoming=[frame])
    client = FilterClient(native_client=native)
    scanned: List[str] = []

    class Service:
        def scan_file(self, path):
            scanned.append(str(path))
            return fail_open_verdict("no matching rule")

    class StopAfterRequest:
        def __init__(self):
            self.event = threading.Event()

        def is_set(self):
            return self.event.is_set()

        def wait(self, seconds):
            return self.event.wait(seconds)

    stop_event = StopAfterRequest()

    class ReplySignalsStop(_FakeNative):
        def reply(self, message_id: int, data: bytes) -> bool:
            result = super().reply(message_id, data)
            stop_event.event.set()
            return result

    native = ReplySignalsStop(incoming=[frame])
    client = FilterClient(native_client=native)
    count = client.run_until_stopped(Service(), stop_event, idle_delay_seconds=0)

    assert count == 1
    assert scanned == [r"C:\x.exe"]
    assert len(native.reply_calls) == 1


def test_run_until_stopped_reconnects_after_transport_failure() -> None:
    frame = encode_filter_request(
        FilterRequest(request_id=23, operation="create", path=r"C:\x.exe")
    )

    class ReconnectingNative(_FakeNative):
        def __init__(self):
            super().__init__(incoming=[frame])
            self.connect_count = 0
            self.receive_count = 0

        def connect(self, port_name: str, timeout_ms: int) -> bool:
            self.connect_count += 1
            return True

        def receive(self, timeout_ms: int):
            self.receive_count += 1
            # Fail every receive on the first connection so competing pump
            # workers cannot consume the request before the reconnect path.
            if self.connect_count == 1:
                raise FilterTransportError("port closed")
            return super().receive(timeout_ms)

    native = ReconnectingNative()
    client = FilterClient(native_client=native)

    class Service:
        def scan_file(self, _path):
            return fail_open_verdict("test")

    class StopOnReply:
        def is_set(self):
            return bool(native.reply_calls)

        def wait(self, _seconds):
            return bool(native.reply_calls)

    count = client.run_until_stopped(
        Service(), StopOnReply(),
        retry_delay_seconds=0, idle_delay_seconds=0,
    )

    assert count == 1
    assert native.connect_count == 2
    assert len(native.reply_calls) == 1


def test_run_keeps_receive_pending_during_scan_and_captures_completion() -> None:
    request = encode_filter_request(
        FilterRequest(request_id=24, operation="create", path=r"C:\x.exe")
    )
    completion = encode_filter_completion(
        FilterCompletion(request_id=24, final_io_status="STATUS_ACCESS_DENIED")
    )
    native = _PendingReceiveNative(request, completion)
    store = _FakeStore()
    client = FilterClient(native_client=native)
    scan_saw_pending_receive: List[bool] = []

    class Service:
        def scan_file(self, _path):
            scan_saw_pending_receive.append(native.pending_event.wait(0.25))
            return _block_verdict()

    class StopOnCompletion:
        def is_set(self):
            return store.completion_event.is_set()

        def wait(self, timeout):
            return store.completion_event.wait(timeout)

    count = client.run_until_stopped(
        Service(), StopOnCompletion(), protection_store=store,
        retry_delay_seconds=0, idle_delay_seconds=0.01,
    )

    assert count == 1
    assert scan_saw_pending_receive == [True]
    assert native.pending_at_reply
    assert store.completions == [("24", "STATUS_ACCESS_DENIED")]


def test_windows_native_client_uses_filter_get_and_reply_contract() -> None:
    frame = encode_filter_request(
        FilterRequest(request_id=22, operation="create", path=r"C:\x.exe")
    )
    message_id = 0x12345678
    incoming = struct.pack("<IIQ", 4096, 0, message_id) + frame
    fltlib = _FakeFltLib(incoming)
    kernel32 = _FakeKernel32(len(incoming))
    native = WindowsNativeClient(
        fltlib=fltlib,
        kernel32=kernel32,
    )
    assert native.connect(r"\STAIProtectionPort", 100)
    assert fltlib.connect_name == r"\STAIProtectionPort"

    message = native.receive(100)

    assert message is not None
    assert message.message_id == message_id
    assert message.payload == frame
    assert message.expects_reply
    assert fltlib.get_message_arg_count == 4

    reply = encode_filter_reply(FilterReply(request_id=22, verdict=fail_open_verdict()))
    assert native.reply(message.message_id, reply)
    assert fltlib.reply_calls == [(message_id, 16 + len(reply), reply)]
    assert fltlib.reply_header_bytes == struct.pack("<iIQ", 0, 0, message_id)

    native.close()
    assert kernel32.closed_handles == [1, 0x1234]


# --- blocked count comes only from a confirmed denied completion -------------

def test_block_counted_only_on_completion_not_reply() -> None:
    native = _FakeNative(incoming=[
        encode_filter_request(FilterRequest(request_id=3, operation="create", path=r"C:\x.exe")),
        encode_filter_completion(
            FilterCompletion(request_id=3, final_io_status="STATUS_ACCESS_DENIED")
        ),
    ])
    store = _FakeStore()
    client = FilterClient(native_client=native)
    client.set_protection_store(store)
    client.connect()
    request = client.receive()
    assert request is not None
    client.reply(3, _block_verdict())
    assert store.completions == []
    # Only a driver-originated completion records a blocked outcome.
    assert client.receive() is None
    assert store.completions == [("3", "STATUS_ACCESS_DENIED")]


def test_completion_non_denied_does_not_record_blocked() -> None:
    native = _FakeNative(incoming=[encode_filter_completion(
        FilterCompletion(request_id=4, final_io_status="STATUS_SUCCESS")
    )])
    store = _FakeStore()
    client = FilterClient(native_client=native)
    client.set_protection_store(store)
    client.connect()
    assert client.receive() is None
    assert store.completions == []


# --- factory stays safe offline ----------------------------------------------

def test_create_filter_client_offline_is_safe() -> None:
    client = create_filter_client(native_client=_FakeNative(connect_ok=False))
    client.connect()  # cannot connect without a driver; must not raise
    assert client.receive() is None  # no phantom request to block
