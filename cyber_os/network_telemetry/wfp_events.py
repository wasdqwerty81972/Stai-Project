"""Read-only wrapper for the optional native WFP net-event subscription bridge.

This module never changes WFP engine options or installs filters.  The native
bridge only subscribes to events already emitted by Windows Filtering
Platform and copies supported fields into a bounded queue.
"""

from __future__ import annotations

import ctypes
import os
import socket
import threading
from collections import deque
from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol


NATIVE_EVENT_VERSION = 1
NATIVE_STATS_VERSION = 1
MAX_APP_ID_BYTES = 256
MAX_SID_BYTES = 68
MAX_POLL_EVENTS = 1024

FIELD_TIMESTAMP = 1 << 0
FIELD_IP_VERSION = 1 << 1
FIELD_PROTOCOL = 1 << 2
FIELD_LOCAL_ADDRESS = 1 << 3
FIELD_REMOTE_ADDRESS = 1 << 4
FIELD_LOCAL_PORT = 1 << 5
FIELD_REMOTE_PORT = 1 << 6
FIELD_APP_ID = 1 << 7
FIELD_USER_SID = 1 << 8
FIELD_DIRECTION = 1 << 9
FIELD_LAYER = 1 << 10
FIELD_LOOPBACK = 1 << 11
FIELD_REAUTH_REASON = 1 << 12
FIELD_APP_ID_TRUNCATED = 1 << 13
FIELD_USER_SID_TRUNCATED = 1 << 14

EVENT_CLASSIFY_ALLOW = 1
EVENT_CLASSIFY_DROP = 2
DIRECTION_UNKNOWN = 0
DIRECTION_INBOUND = 1
DIRECTION_OUTBOUND = 2

ERROR_SUCCESS = 0
ERROR_BUSY = 170
ERROR_NO_MORE_ITEMS = 259


class WfpSubscriptionError(RuntimeError):
    """Raised when the native subscription bridge cannot start or read."""

    def __init__(self, operation: str, error_code: int, detail: str | None = None):
        message = detail or f"{operation} failed with Windows error {error_code}"
        super().__init__(message)
        self.operation = operation
        self.error_code = error_code


class NativeEventRecord(ctypes.Structure):
    """Packed, versioned ABI record copied by the native callback."""

    _pack_ = 1
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("version", ctypes.c_uint32),
        ("sequence", ctypes.c_uint64),
        ("timestamp_filetime", ctypes.c_uint64),
        ("field_flags", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("ip_version", ctypes.c_uint32),
        ("protocol", ctypes.c_uint32),
        ("direction", ctypes.c_uint32),
        ("layer_id", ctypes.c_uint32),
        ("reauth_reason", ctypes.c_uint32),
        ("is_loopback", ctypes.c_uint32),
        ("local_port", ctypes.c_uint16),
        ("remote_port", ctypes.c_uint16),
        ("local_address", ctypes.c_uint8 * 16),
        ("remote_address", ctypes.c_uint8 * 16),
        ("app_id_len", ctypes.c_uint32),
        ("app_id", ctypes.c_uint8 * MAX_APP_ID_BYTES),
        ("user_sid_len", ctypes.c_uint32),
        ("user_sid", ctypes.c_uint8 * MAX_SID_BYTES),
    ]


class NativeStatsRecord(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("version", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        ("queued", ctypes.c_uint32),
        ("last_sequence", ctypes.c_uint64),
        ("dropped", ctypes.c_uint64),
        ("last_error", ctypes.c_uint32),
    ]


@dataclass(frozen=True, slots=True)
class WfpNetEvent:
    """Observed WFP classify event; fields stay absent when Windows omits them."""

    sequence: int
    timestamp_utc: str | None
    event_type: str
    observed_action: str
    ip_version: int | None
    protocol: int | None
    local_address: str | None
    remote_address: str | None
    local_port: int | None
    remote_port: int | None
    app_id_hex: str | None
    app_id_truncated: bool
    user_sid: str | None
    direction: str | None
    layer_id: int | None
    reauth_reason: int | None
    is_loopback: bool | None
    process_id: None = None


@dataclass(frozen=True, slots=True)
class WfpBridgeStats:
    state: str
    queued: int
    dropped: int
    last_sequence: int
    last_error: int


class NativeBridge(Protocol):
    def start(self) -> int: ...
    def stop(self) -> int: ...
    def read_one(self) -> NativeEventRecord | None: ...
    def stats(self) -> dict[str, Any]: ...


def _decode_sid(raw: bytes) -> str:
    if len(raw) < 8:
        raise ValueError("SID is shorter than its fixed header")
    revision, subauthority_count = raw[0], raw[1]
    expected = 8 + 4 * subauthority_count
    if revision != 1 or expected != len(raw) or expected > MAX_SID_BYTES:
        raise ValueError("SID encoding is invalid")
    identifier_authority = int.from_bytes(raw[2:8], "big")
    subauthorities = [
        str(int.from_bytes(raw[offset : offset + 4], "little"))
        for offset in range(8, expected, 4)
    ]
    suffix = "" if not subauthorities else "-" + "-".join(subauthorities)
    return f"S-{revision}-{identifier_authority}{suffix}"


def _address(record: NativeEventRecord, name: str, ip_version: int) -> str:
    raw = bytes(getattr(record, name))
    width = 4 if ip_version == 4 else 16
    return socket.inet_ntop(socket.AF_INET if ip_version == 4 else socket.AF_INET6, raw[:width])


def _timestamp_from_filetime(value: int) -> str:
    # Windows FILETIME counts 100 ns intervals since 1601-01-01 UTC.
    instant = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)
    return instant.isoformat()


def decode_native_event(record: NativeEventRecord) -> WfpNetEvent:
    """Validate and normalize one fixed ABI record without guessing missing data."""

    if not isinstance(record, NativeEventRecord):
        raise ValueError("native WFP event has the wrong record type")
    if record.size != ctypes.sizeof(NativeEventRecord):
        raise ValueError("native WFP event size does not match this ABI")
    if record.version != NATIVE_EVENT_VERSION:
        raise ValueError(f"unsupported native WFP event version {record.version}")
    if record.sequence <= 0:
        raise ValueError("native WFP event sequence must be positive")
    if record.event_type == EVENT_CLASSIFY_ALLOW:
        event_type, action = "classify_allow", "allow"
    elif record.event_type == EVENT_CLASSIFY_DROP:
        event_type, action = "classify_drop", "drop"
    else:
        raise ValueError("native WFP event type is unsupported")

    flags = record.field_flags
    ip_version = None
    if flags & FIELD_IP_VERSION:
        if record.ip_version not in (4, 6):
            raise ValueError("native WFP event IP version is invalid")
        ip_version = int(record.ip_version)

    local_address = None
    remote_address = None
    if ip_version is not None and flags & FIELD_LOCAL_ADDRESS:
        local_address = _address(record, "local_address", ip_version)
    if ip_version is not None and flags & FIELD_REMOTE_ADDRESS:
        remote_address = _address(record, "remote_address", ip_version)

    app_id_hex = None
    if flags & FIELD_APP_ID:
        if record.app_id_len > MAX_APP_ID_BYTES:
            raise ValueError("native WFP application identifier length is invalid")
        if not flags & FIELD_APP_ID_TRUNCATED:
            app_id_hex = bytes(record.app_id[: record.app_id_len]).hex()

    user_sid = None
    if flags & FIELD_USER_SID:
        if record.user_sid_len > MAX_SID_BYTES:
            raise ValueError("native WFP user SID length is invalid")
        if not flags & FIELD_USER_SID_TRUNCATED:
            user_sid = _decode_sid(bytes(record.user_sid[: record.user_sid_len]))

    direction = None
    if flags & FIELD_DIRECTION:
        if record.direction == DIRECTION_INBOUND:
            direction = "inbound"
        elif record.direction == DIRECTION_OUTBOUND:
            direction = "outbound"
        else:
            raise ValueError("native WFP event direction is invalid")

    timestamp = None
    if flags & FIELD_TIMESTAMP:
        try:
            timestamp = _timestamp_from_filetime(record.timestamp_filetime)
        except (OverflowError, ValueError) as exc:
            raise ValueError("native WFP event timestamp is invalid") from exc

    return WfpNetEvent(
        sequence=int(record.sequence),
        timestamp_utc=timestamp,
        event_type=event_type,
        observed_action=action,
        ip_version=ip_version,
        protocol=int(record.protocol) if flags & FIELD_PROTOCOL else None,
        local_address=local_address,
        remote_address=remote_address,
        local_port=int(record.local_port) if flags & FIELD_LOCAL_PORT else None,
        remote_port=int(record.remote_port) if flags & FIELD_REMOTE_PORT else None,
        app_id_hex=app_id_hex,
        app_id_truncated=bool(flags & FIELD_APP_ID_TRUNCATED),
        user_sid=user_sid,
        direction=direction,
        layer_id=int(record.layer_id) if flags & FIELD_LAYER else None,
        reauth_reason=(
            int(record.reauth_reason) if flags & FIELD_REAUTH_REASON else None
        ),
        is_loopback=(bool(record.is_loopback) if flags & FIELD_LOOPBACK else None),
        process_id=None,
    )


class _CtypesBridge:
    """Small ctypes adapter for the optional x64 native bridge DLL."""

    def __init__(self, dll_path: str | os.PathLike[str]):
        if os.name != "nt":
            raise WfpSubscriptionError("load", 50, "WFP event bridge is Windows-only")
        path = Path(dll_path).expanduser().resolve()
        try:
            library = ctypes.WinDLL(str(path), use_last_error=True)
        except OSError as exc:
            raise WfpSubscriptionError("load", ctypes.get_last_error(), str(exc)) from exc
        self._library = library
        self._configure()

    def _configure(self) -> None:
        library = self._library
        library.SvsWfpStart.argtypes = []
        library.SvsWfpStart.restype = ctypes.c_uint32
        library.SvsWfpStop.argtypes = []
        library.SvsWfpStop.restype = ctypes.c_uint32
        library.SvsWfpReadNext.argtypes = [
            ctypes.POINTER(NativeEventRecord),
            ctypes.c_uint32,
        ]
        library.SvsWfpReadNext.restype = ctypes.c_uint32
        library.SvsWfpGetStats.argtypes = [ctypes.POINTER(NativeStatsRecord)]
        library.SvsWfpGetStats.restype = ctypes.c_uint32

    def start(self) -> int:
        return int(self._library.SvsWfpStart())

    def stop(self) -> int:
        return int(self._library.SvsWfpStop())

    def read_one(self) -> NativeEventRecord | None:
        record = NativeEventRecord()
        result = int(
            self._library.SvsWfpReadNext(
                ctypes.byref(record), ctypes.sizeof(NativeEventRecord)
            )
        )
        if result in (ERROR_NO_MORE_ITEMS, ERROR_BUSY):
            return None
        if result != ERROR_SUCCESS:
            raise WfpSubscriptionError("read", result)
        return record

    def stats(self) -> dict[str, int]:
        record = NativeStatsRecord()
        record.size = ctypes.sizeof(NativeStatsRecord)
        record.version = NATIVE_STATS_VERSION
        result = int(self._library.SvsWfpGetStats(ctypes.byref(record)))
        if result != ERROR_SUCCESS:
            raise WfpSubscriptionError("stats", result)
        if record.size != ctypes.sizeof(NativeStatsRecord):
            raise WfpSubscriptionError("stats", 13, "native stats size mismatch")
        if record.version != NATIVE_STATS_VERSION:
            raise WfpSubscriptionError("stats", 13, "native stats version mismatch")
        return {
            "state": int(record.state),
            "queued": int(record.queued),
            "dropped": int(record.dropped),
            "last_sequence": int(record.last_sequence),
            "last_error": int(record.last_error),
        }


class WfpNetEventSubscription:
    """Explicit lifecycle wrapper; construction itself never subscribes."""

    def __init__(
        self,
        bridge: NativeBridge | None = None,
        *,
        dll_path: str | os.PathLike[str] | None = None,
    ) -> None:
        if bridge is None:
            selected_path = dll_path or os.environ.get("STAI_WFP_EVENT_BRIDGE")
            if not selected_path:
                raise WfpSubscriptionError(
                    "load", 2, "pass dll_path or set STAI_WFP_EVENT_BRIDGE"
                )
            bridge = _CtypesBridge(selected_path)
        self._bridge = bridge
        self._started = False

    def start(self) -> None:
        if self._started:
            raise WfpSubscriptionError("start", 183, "subscription is already started")
        result = int(self._bridge.start())
        if result != ERROR_SUCCESS:
            raise WfpSubscriptionError("start", result)
        self._started = True

    def poll(self, *, max_events: int = 128) -> list[WfpNetEvent]:
        if not self._started:
            raise WfpSubscriptionError("read", 1062, "subscription is not started")
        if not isinstance(max_events, int) or isinstance(max_events, bool):
            raise ValueError("max_events must be an integer")
        if not 1 <= max_events <= MAX_POLL_EVENTS:
            raise ValueError(f"max_events must be between 1 and {MAX_POLL_EVENTS}")
        events: list[WfpNetEvent] = []
        for _ in range(max_events):
            record = self._bridge.read_one()
            if record is None:
                break
            events.append(decode_native_event(record))
        return events

    def stats(self) -> WfpBridgeStats:
        raw = self._bridge.stats()
        return WfpBridgeStats(
            state=_state_name(raw.get("state")),
            queued=_bounded_stat(raw.get("queued"), "queued"),
            dropped=_bounded_stat(raw.get("dropped"), "dropped"),
            last_sequence=_bounded_stat(raw.get("last_sequence"), "last_sequence"),
            last_error=_bounded_stat(raw.get("last_error"), "last_error"),
        )

    def close(self) -> None:
        if not self._started:
            return
        result = int(self._bridge.stop())
        if result != ERROR_SUCCESS:
            raise WfpSubscriptionError("stop", result)
        self._started = False

    def __enter__(self) -> WfpNetEventSubscription:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        del exc_type, exc_value, traceback
        self.close()


class WfpNetEventMonitor:
    """Optional service-friendly poller with bounded in-memory event history.

    Construction and module import do not load the native DLL. ``start`` is
    deliberately non-throwing so a missing bridge or unsupported Windows build
    can be reported as an unavailable capability without failing service boot.
    """

    def __init__(
        self,
        *,
        bridge: NativeBridge | None = None,
        dll_path: str | os.PathLike[str] | None = None,
        poll_interval: float = 0.1,
        history_limit: int = 2048,
        batch_size: int = 128,
    ) -> None:
        if not isinstance(poll_interval, (int, float)) or poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if not isinstance(history_limit, int) or isinstance(history_limit, bool) or history_limit < 1:
            raise ValueError("history_limit must be a positive integer")
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or not 1 <= batch_size <= MAX_POLL_EVENTS:
            raise ValueError(f"batch_size must be between 1 and {MAX_POLL_EVENTS}")
        self._bridge = bridge
        self._dll_path = dll_path
        self._poll_interval = float(poll_interval)
        self._batch_size = batch_size
        self._events: deque[WfpNetEvent] = deque(maxlen=history_limit)
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._subscription: WfpNetEventSubscription | None = None
        self._state = "stopped"
        self._last_error: str | None = None
        self._available = False

    def start(self) -> bool:
        """Start subscription and background polling, returning capability status."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return True
            self._last_error = None
            try:
                if self._subscription is None:
                    self._subscription = WfpNetEventSubscription(
                        self._bridge,
                        dll_path=self._dll_path,
                    )
                self._subscription.start()
            except Exception as exc:
                self._state = "unavailable"
                self._last_error = str(exc) or type(exc).__name__
                self._subscription = None
                return False

            self._stop_event.clear()
            self._state = "running"
            self._available = True
            self._thread = threading.Thread(
                target=self._poll_loop,
                name="svs-wfp-net-events",
                daemon=True,
            )
            self._thread.start()
            return True

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                subscription = self._subscription
                if subscription is None:
                    raise WfpSubscriptionError("read", 6, "subscription is unavailable")
                events = subscription.poll(max_events=self._batch_size)
                if events:
                    with self._lock:
                        self._events.extend(events)
                    continue
            except Exception as exc:
                with self._lock:
                    self._state = "failed"
                    self._last_error = str(exc) or type(exc).__name__
                self._stop_event.set()
                return
            self._stop_event.wait(self._poll_interval)

    def stop(self, timeout: float = 5.0) -> bool:
        """Stop polling and unsubscribe; return false only on timeout/failure."""
        if not isinstance(timeout, (int, float)) or timeout < 0:
            with self._lock:
                self._last_error = "timeout must be a non-negative number"
            return False
        with self._lock:
            thread = self._thread
            self._stop_event.set()
        if thread is not None and thread.is_alive():
            thread.join(float(timeout))
            if thread.is_alive():
                with self._lock:
                    self._last_error = "timed out waiting for WFP event polling to stop"
                return False

        with self._lock:
            try:
                if self._subscription is not None:
                    self._subscription.close()
            except Exception as exc:
                self._state = "failed"
                self._last_error = str(exc) or type(exc).__name__
                return False
            self._thread = None
            self._state = "stopped"
            return True

    def get_status(self) -> dict[str, Any]:
        """Return a JSON-safe status snapshot suitable for a service health API."""
        with self._lock:
            status: dict[str, Any] = {
                "state": self._state,
                "available": self._available,
                "running": self._state == "running",
                "last_error": self._last_error,
                "event_count": len(self._events),
            }
            subscription = self._subscription
        if subscription is not None:
            try:
                native = subscription.stats()
                status.update(
                    queued=native.queued,
                    dropped=native.dropped,
                    last_sequence=native.last_sequence,
                    native_state=native.state,
                    native_error=native.last_error,
                )
            except Exception as exc:
                status["native_error"] = str(exc) or type(exc).__name__
        else:
            status.update(queued=0, dropped=0, last_sequence=0)
        return status

    def snapshot(self) -> list[dict[str, Any]]:
        """Return a copy of the bounded history as JSON-safe dictionaries."""
        with self._lock:
            return [asdict(event) for event in self._events]


def _bounded_stat(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"native {name} statistic is invalid")
    return value


def _state_name(value: Any) -> str:
    if isinstance(value, str):
        return value
    return {
        0: "stopped",
        1: "starting",
        2: "running",
        3: "stopping",
        4: "failed",
    }.get(value, "unknown")
