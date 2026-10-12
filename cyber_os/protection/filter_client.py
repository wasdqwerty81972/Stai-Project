"""FltLib wrapper and service-side request loop for the STAI minifilter."""

from __future__ import annotations

import ctypes
import os
import queue
import sys
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ctypes import wintypes

from .filter_protocol import (
    MAX_PAYLOAD_SIZE,
    FilterCompletion,
    FilterReply,
    FilterRequest,
    ProtocolError,
    decode_filter_completion,
    decode_filter_reply,
    decode_filter_request,
    encode_filter_reply,
)
from .models import ScanVerdict


FAIL_OPEN_RULE_VERSION = "unknown"
_FILTER_MESSAGE_HEADER_SIZE = 16
_FILTER_REPLY_HEADER_SIZE = 16
_HRESULT_IO_PENDING = 0x800703E5
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 0x102
_INFINITE = 0xFFFFFFFF
_RECEIVE_WORKER_COUNT = 2
_RECEIVE_POLL_TIMEOUT_MS = 250


class FilterTransportError(ConnectionError):
    """The Filter Manager communication handle can no longer receive data."""


class _FILTER_MESSAGE_HEADER(ctypes.Structure):
    """Native FILTER_MESSAGE_HEADER layout, including x64 padding."""

    _fields_ = [
        ("ReplyLength", wintypes.DWORD),
        ("_Padding", wintypes.DWORD),
        ("MessageId", ctypes.c_ulonglong),
    ]


class _FILTER_REPLY_HEADER(ctypes.Structure):
    """Native FILTER_REPLY_HEADER layout, including x64 padding."""

    _fields_ = [
        ("Status", wintypes.LONG),
        ("_Padding", wintypes.DWORD),
        ("MessageId", ctypes.c_ulonglong),
    ]


class _OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


@dataclass(slots=True)
class FilterClientConfig:
    port_name: str = r"\STAIProtectionPort"
    timeout_ms: int = 5000


@dataclass(frozen=True, slots=True)
class NativeFilterMessage:
    """One Filter Manager message, with its OS reply token kept separate."""

    message_id: int
    payload: bytes
    reply_length: int

    @property
    def expects_reply(self) -> bool:
        return self.reply_length > 0


def _service_scan_path(path: str, *, windows: Optional[bool] = None) -> Path:
    """Translate kernel NT names into paths the Windows service can open."""
    is_windows = os.name == "nt" if windows is None else windows
    normalized = path.replace("/", "\\")
    if is_windows and normalized.casefold().startswith("\\device\\"):
        normalized = "\\\\?\\GLOBALROOT" + normalized
    elif is_windows and normalized.casefold().startswith("\\??\\unc\\"):
        normalized = "\\\\?\\UNC\\" + normalized[8:]
    elif is_windows and normalized.casefold().startswith("\\??\\"):
        normalized = "\\\\?\\" + normalized[4:]
    return Path(normalized)


def fail_open_verdict(
    reason: str = "service unavailable",
    rule_version: str = FAIL_OPEN_RULE_VERSION,
) -> ScanVerdict:
    """Return an unknown verdict that can never deny I/O."""
    return ScanVerdict(
        status="unknown",
        action="allow",
        rule_id=None,
        rule_version=rule_version,
        sha256=None,
        reason=reason,
    )


class NativeFilterClient(ABC):
    """Abstract Filter Manager transport; injectable for offline tests."""

    @abstractmethod
    def connect(self, port_name: str, timeout_ms: int) -> bool:
        raise NotImplementedError

    @abstractmethod
    def receive(self, timeout_ms: int) -> Optional[NativeFilterMessage]:
        raise NotImplementedError

    @abstractmethod
    def reply(self, message_id: int, data: bytes) -> bool:
        """Reply to one driver-originated message via FilterReplyMessage."""
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        raise NotImplementedError


class WindowsNativeClient(NativeFilterClient):
    """Windows implementation using the Filter Manager user-mode API."""

    def __init__(self, fltlib: Any = None, kernel32: Any = None) -> None:
        self._handle: Any = None
        self._fltlib: Any = fltlib
        self._kernel32: Any = kernel32
        if self._fltlib is None or self._kernel32 is None:
            self._load_fltlib()
        if self._fltlib is not None and self._kernel32 is not None:
            self._configure_api_signatures()

    def _load_fltlib(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("FltLib is only available on Windows")
        try:
            self._fltlib = ctypes.WinDLL("fltlib.dll")
            self._kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
            self._configure_api_signatures()
        except (OSError, AttributeError):
            self._fltlib = None
            self._kernel32 = None

    def _configure_api_signatures(self) -> None:
        if not self._fltlib or not self._kernel32:
            return

        self._fltlib.FilterConnectCommunicationPort.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.WORD,
            wintypes.LPVOID,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        self._fltlib.FilterConnectCommunicationPort.restype = wintypes.LONG
        self._fltlib.FilterGetMessage.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_FILTER_MESSAGE_HEADER),
            wintypes.DWORD,
            ctypes.POINTER(_OVERLAPPED),
        ]
        self._fltlib.FilterGetMessage.restype = wintypes.LONG
        self._fltlib.FilterReplyMessage.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_FILTER_REPLY_HEADER),
            wintypes.DWORD,
        ]
        self._fltlib.FilterReplyMessage.restype = wintypes.LONG
        self._kernel32.CreateEventW.argtypes = [
            wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR,
        ]
        self._kernel32.CreateEventW.restype = wintypes.HANDLE
        self._kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self._kernel32.WaitForSingleObject.restype = wintypes.DWORD
        self._kernel32.GetOverlappedResult.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(_OVERLAPPED),
            ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
        ]
        self._kernel32.GetOverlappedResult.restype = wintypes.BOOL
        self._kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(_OVERLAPPED)]
        self._kernel32.CancelIoEx.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL

    def connect(self, port_name: str, timeout_ms: int) -> bool:
        del timeout_ms  # FilterConnectCommunicationPort has no timeout parameter.
        if not self._fltlib:
            return False

        handle = wintypes.HANDLE()
        hr = self._fltlib.FilterConnectCommunicationPort(
            port_name, 0, None, 0, None, ctypes.byref(handle)
        )
        if int(hr) & 0xFFFFFFFF == 0:
            self._handle = handle
            return True
        return False

    def receive(self, timeout_ms: int) -> Optional[NativeFilterMessage]:
        if not self._fltlib or not self._kernel32 or not self._handle:
            if self._fltlib and self._kernel32:
                raise FilterTransportError("Filter Manager port is disconnected")
            return None

        header_size = ctypes.sizeof(_FILTER_MESSAGE_HEADER)
        if header_size != _FILTER_MESSAGE_HEADER_SIZE:
            return None
        buffer = ctypes.create_string_buffer(header_size + MAX_PAYLOAD_SIZE)
        event = self._kernel32.CreateEventW(None, True, False, None)
        if not event:
            return None

        overlapped = _OVERLAPPED()
        overlapped.hEvent = event
        bytes_returned = wintypes.DWORD(0)
        try:
            hr = self._fltlib.FilterGetMessage(
                self._handle,
                ctypes.cast(buffer, ctypes.POINTER(_FILTER_MESSAGE_HEADER)),
                len(buffer),
                ctypes.byref(overlapped),
            )
            hr_code = int(hr) & 0xFFFFFFFF
            if hr_code not in (0, _HRESULT_IO_PENDING):
                self.close()
                raise FilterTransportError(f"FilterGetMessage failed: 0x{hr_code:08X}")

            if hr_code == _HRESULT_IO_PENDING:
                wait_result = self._kernel32.WaitForSingleObject(event, max(0, timeout_ms))
                if wait_result == _WAIT_TIMEOUT:
                    self._kernel32.CancelIoEx(self._handle, ctypes.byref(overlapped))
                    self._kernel32.WaitForSingleObject(event, _INFINITE)
                    self._kernel32.GetOverlappedResult(
                        self._handle, ctypes.byref(overlapped),
                        ctypes.byref(bytes_returned), False,
                    )
                    return None
                if wait_result != _WAIT_OBJECT_0:
                    self._kernel32.CancelIoEx(self._handle, ctypes.byref(overlapped))
                    self._kernel32.WaitForSingleObject(event, _INFINITE)
                    self.close()
                    raise FilterTransportError(
                        f"waiting for FilterGetMessage failed: 0x{int(wait_result):08X}"
                    )

            if not self._kernel32.GetOverlappedResult(
                self._handle, ctypes.byref(overlapped), ctypes.byref(bytes_returned), False
            ):
                self.close()
                raise FilterTransportError("FilterGetMessage completion failed")

            received_size = int(bytes_returned.value)
            if received_size < header_size or received_size > len(buffer):
                return None
            header = ctypes.cast(buffer, ctypes.POINTER(_FILTER_MESSAGE_HEADER)).contents
            payload_size = received_size - header_size
            if not header.MessageId or header.ReplyLength > MAX_PAYLOAD_SIZE + _FILTER_REPLY_HEADER_SIZE:
                return None
            payload = ctypes.string_at(ctypes.addressof(buffer) + header_size, payload_size)
            return NativeFilterMessage(
                message_id=int(header.MessageId),
                payload=payload,
                reply_length=int(header.ReplyLength),
            )
        finally:
            self._kernel32.CloseHandle(event)

    def reply(self, message_id: int, data: bytes) -> bool:
        if not self._fltlib or not self._handle or not message_id:
            return False
        header_size = ctypes.sizeof(_FILTER_REPLY_HEADER)
        if header_size != _FILTER_REPLY_HEADER_SIZE:
            return False

        buffer = ctypes.create_string_buffer(header_size + len(data))
        header = ctypes.cast(buffer, ctypes.POINTER(_FILTER_REPLY_HEADER)).contents
        header.Status = 0  # STATUS_SUCCESS; verdict is in the protocol payload.
        header.MessageId = message_id
        if data:
            ctypes.memmove(ctypes.addressof(buffer) + header_size, data, len(data))
        hr = self._fltlib.FilterReplyMessage(
            self._handle,
            ctypes.cast(buffer, ctypes.POINTER(_FILTER_REPLY_HEADER)),
            header_size + len(data),
        )
        succeeded = (int(hr) & 0xFFFFFFFF) == 0
        if not succeeded:
            self.close()
        return succeeded

    def close(self) -> None:
        if self._kernel32 and self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


class FilterClient:
    """Service-side client that scans requests and returns typed verdicts."""

    def __init__(
        self,
        config: Optional[FilterClientConfig] = None,
        native_client: Optional[NativeFilterClient] = None,
    ) -> None:
        self._config = config or FilterClientConfig()
        self._native = native_client
        self._connected = False
        self._protection_store: Any = None
        self._pending_messages: dict[int, NativeFilterMessage] = {}
        self._pending_lock = threading.Lock()

    def set_protection_store(self, store: Any) -> None:
        """Set the store that records driver-confirmed completions."""
        self._protection_store = store

    def connect(self) -> bool:
        if self._connected:
            return True
        if self._native is None:
            try:
                self._native = WindowsNativeClient()
            except RuntimeError:
                return False
        self._connected = bool(
            self._native and self._native.connect(
                self._config.port_name, self._config.timeout_ms
            )
        )
        return self._connected

    def receive(self) -> Optional[FilterRequest]:
        if not self._connected or not self._native:
            return None
        message = self._native.receive(self._config.timeout_ms)
        if message is None:
            return None

        return self._handle_native_message(message)

    def _handle_native_message(self, message: NativeFilterMessage) -> Optional[FilterRequest]:
        try:
            request = decode_filter_request(message.payload)
        except ProtocolError:
            try:
                completion = decode_filter_completion(message.payload)
            except ProtocolError:
                return None
            if not message.expects_reply:
                self._record_driver_completion(completion)
            return None

        if not message.expects_reply:
            return None
        with self._pending_lock:
            if request.request_id in self._pending_messages:
                return None
            self._pending_messages[request.request_id] = message
        return request

    def process_next(self, service: Any) -> Optional[FilterRequest]:
        """Scan one received request and reply; errors become fail-open allows."""
        request = self.receive()
        if request is None:
            return None
        self._scan_request(service, request)
        return request

    def _scan_request(self, service: Any, request: FilterRequest) -> None:
        try:
            verdict = service.scan_file(_service_scan_path(request.path))
            if not isinstance(verdict, ScanVerdict):
                raise TypeError("protection service returned a malformed verdict")
        except Exception as exc:
            self.reply_fail_open(request.request_id, f"scan failed: {exc}")
        else:
            self.reply(request.request_id, verdict)

    def _receive_pump(
        self,
        stop_event: threading.Event,
        request_queue: queue.Queue[Any],
    ) -> None:
        """Keep overlapped receives posted while scan/reply work runs elsewhere."""
        while not stop_event.is_set():
            try:
                if not self._native:
                    raise FilterTransportError("Filter Manager client is unavailable")
                message = self._native.receive(
                    min(self._config.timeout_ms, _RECEIVE_POLL_TIMEOUT_MS)
                )
            except Exception as exc:
                request_queue.put(exc)
                return

            if message is None:
                stop_event.wait(0.005)
                continue

            request = self._handle_native_message(message)
            if request is not None:
                # The driver caps outstanding requests at 32; keeping this
                # queue bounded prevents an unbounded service-side backlog.
                request_queue.put(request)

    def run_until_stopped(
        self,
        service: Any,
        stop_event: Any,
        *,
        protection_store: Any = None,
        retry_delay_seconds: float = 1.0,
        idle_delay_seconds: float = 0.05,
    ) -> int:
        """Run the bounded receive/scan/reply loop until ``stop_event`` is set.

        The native receive call is bounded by ``config.timeout_ms``. A failed
        connection or transport error is retried after a bounded, interruptible
        delay. This is an adapter for a service host to call; it does not itself
        register or start a Windows service.
        """
        if protection_store is not None:
            self.set_protection_store(protection_store)

        processed = 0
        retry_delay = max(0.0, retry_delay_seconds)
        idle_delay = max(0.01, idle_delay_seconds)
        while not stop_event.is_set():
            try:
                connected = self._connected or self.connect()
            except Exception:
                connected = False
            if not connected:
                if stop_event.wait(retry_delay):
                    break
                continue

            request_queue: queue.Queue[Any] = queue.Queue(maxsize=32)
            receive_stop = threading.Event()
            receivers = [
                threading.Thread(
                    target=self._receive_pump,
                    args=(receive_stop, request_queue),
                    name=f"stai-filter-receive-{index}",
                    daemon=True,
                )
                for index in range(_RECEIVE_WORKER_COUNT)
            ]
            for receiver in receivers:
                receiver.start()

            transport_failed = False
            try:
                while not stop_event.is_set():
                    try:
                        item = request_queue.get(timeout=idle_delay)
                    except queue.Empty:
                        if not any(receiver.is_alive() for receiver in receivers):
                            transport_failed = True
                            break
                        continue
                    if isinstance(item, BaseException):
                        transport_failed = True
                        break
                    try:
                        self._scan_request(service, item)
                    except Exception:
                        transport_failed = True
                        break
                    processed += 1
            finally:
                receive_stop.set()
                for receiver in receivers:
                    receiver.join()

            if stop_event.is_set():
                break
            if transport_failed:
                self.close()
                if stop_event.wait(retry_delay):
                    break

        self.close()
        return processed

    def reply(self, request_id: int, verdict: ScanVerdict) -> None:
        if not self._connected or not self._native:
            return
        with self._pending_lock:
            message = self._pending_messages.pop(request_id, None)
        if message is None or not message.expects_reply:
            return

        try:
            encoded = encode_filter_reply(FilterReply(request_id=request_id, verdict=verdict))
            decoded = decode_filter_reply(encoded)
            if decoded.request_id != request_id:
                return
            if message.reply_length and len(encoded) + _FILTER_REPLY_HEADER_SIZE > message.reply_length:
                encoded = encode_filter_reply(
                    FilterReply(request_id=request_id, verdict=fail_open_verdict("reply too large"))
                )
            if message.reply_length and len(encoded) + _FILTER_REPLY_HEADER_SIZE > message.reply_length:
                # Do not send a malformed/oversized reply; the kernel's bounded
                # timeout is the safe fail-open fallback.
                return
            if not self._native.reply(message.message_id, encoded):
                raise FilterTransportError("FilterReplyMessage failed")
        except (ProtocolError, AttributeError, TypeError, ValueError):
            # If even a fail-open frame cannot be made, leave the operation
            # unresolved; the kernel's bounded wait will pass it through.
            return

    def reply_fail_open(self, request_id: int, reason: str = "service unavailable") -> None:
        self.reply(request_id, fail_open_verdict(reason))

    def _record_driver_completion(self, completion: FilterCompletion) -> None:
        if (
            completion.final_io_status == "STATUS_ACCESS_DENIED"
            and self._protection_store
            and hasattr(self._protection_store, "record_filter_completion")
        ):
            self._protection_store.record_filter_completion(
                str(completion.request_id), completion.final_io_status
            )

    def close(self) -> None:
        if self._native:
            self._native.close()
        with self._pending_lock:
            self._pending_messages.clear()
        self._connected = False


class MockFilterClient(FilterClient):
    """Offline implementation for unit tests and non-Windows development."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._queue: list[FilterRequest | FilterCompletion] = []
        self._replies: dict[int, FilterReply] = {}
        self._pending_request_ids: set[int] = set()

    def connect(self) -> bool:
        self._connected = True
        return True

    def receive(self) -> Optional[FilterRequest]:
        if not self._queue:
            return None
        event = self._queue.pop(0)
        if isinstance(event, FilterCompletion):
            self._record_driver_completion(event)
            return None
        self._pending_request_ids.add(event.request_id)
        return event

    def reply(self, request_id: int, verdict: ScanVerdict) -> None:
        if not self._connected or request_id not in self._pending_request_ids:
            return
        self._pending_request_ids.remove(request_id)
        self._replies[request_id] = FilterReply(request_id=request_id, verdict=verdict)

    def close(self) -> None:
        self._pending_request_ids.clear()
        self._connected = False

    def inject_request(self, request: FilterRequest) -> None:
        self._queue.append(request)

    def inject_completion(self, completion: FilterCompletion) -> None:
        self._queue.append(completion)

    def get_last_reply(self, request_id: int) -> Optional[FilterReply]:
        return self._replies.get(request_id)


def create_filter_client(
    config: Optional[FilterClientConfig] = None,
    native_client: Optional[NativeFilterClient] = None,
) -> FilterClient:
    """Create the native client on Windows and a safe mock elsewhere."""
    if sys.platform == "win32":
        return FilterClient(config, native_client)
    return MockFilterClient(config, native_client)
