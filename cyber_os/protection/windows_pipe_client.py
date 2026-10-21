"""Bounded client for the authenticated local protection named pipe."""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

from .windows_service import MAX_FRAME_BYTES, PIPE_NAME, PROTOCOL_VERSION


_RETRYABLE_OPEN_ERRORS = {2, 121, 231}  # FILE_NOT_FOUND, SEM_TIMEOUT, PIPE_BUSY


def _pipe_error_code(error: BaseException) -> int | None:
    code = getattr(error, "winerror", None)
    if code is None and getattr(error, "args", None):
        first = error.args[0]
        if isinstance(first, int):
            code = first
    return code


def _open_pipe(win32pipe: Any, win32file: Any, deadline: float) -> Any:
    """Retry the short gap while the single-instance service pipe is recreated."""
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        remaining_ms = max(1, int(remaining * 1000))
        try:
            win32pipe.WaitNamedPipe(PIPE_NAME, remaining_ms)
            return win32file.CreateFile(
                PIPE_NAME,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None,
            )
        except Exception as exc:
            if _pipe_error_code(exc) not in _RETRYABLE_OPEN_ERRORS:
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("protection service pipe did not become available") from exc
            time.sleep(min(0.05, remaining))
    raise TimeoutError("protection service pipe did not become available")


def _read_exact(handle: Any, size: int, win32file: Any, deadline: float) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        if time.monotonic() >= deadline:
            raise TimeoutError("protection pipe response timed out")
        try:
            _status, chunk = win32file.ReadFile(handle, size - len(chunks))
        except Exception as exc:
            if getattr(exc, "winerror", None) not in {232, 996}:
                raise
            time.sleep(0.01)
            continue
        if not chunk:
            time.sleep(0.01)
            continue
        chunks.extend(chunk)
    return bytes(chunks)


def request_protection_service(operation: str, payload: dict[str, Any], *, timeout: float = 5.0) -> Any:
    """Issue one bounded request; callers receive no response on non-Windows."""
    if os.name != "nt":
        raise OSError("the protection service pipe is available only on Windows")
    import win32file
    import win32pipe

    request_id = uuid.uuid4().hex
    body = json.dumps(
        {"version": PROTOCOL_VERSION, "request_id": request_id, "operation": operation, "payload": payload},
        separators=(",", ":"),
    ).encode("utf-8")
    if not body or len(body) > MAX_FRAME_BYTES:
        raise ValueError("protection pipe request exceeds the frame limit")

    deadline = time.monotonic() + max(0.1, timeout)
    handle = None
    try:
        handle = _open_pipe(win32pipe, win32file, deadline)
        win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_BYTE, None, None)
        win32file.WriteFile(handle, len(body).to_bytes(4, "little") + body)
        header = _read_exact(handle, 4, win32file, deadline)
        length = int.from_bytes(header, "little")
        if length < 1 or length > MAX_FRAME_BYTES:
            raise ValueError("protection service response exceeds the frame limit")
        response = json.loads(_read_exact(handle, length, win32file, deadline).decode("utf-8"))
        if response.get("version") != PROTOCOL_VERSION or response.get("request_id") != request_id:
            raise ValueError("protection service response did not match the request")
        if not response.get("ok"):
            raise RuntimeError(str(response.get("error") or "protection pipe request failed"))
        return response.get("data")
    finally:
        if handle is not None:
            win32file.CloseHandle(handle)


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"protection service returned malformed {label} data")
    return value


def get_process_snapshot_page(
    *, offset: int = 0, limit: int = 100, sequence: int | None = None, timeout: float = 5.0
) -> dict[str, Any]:
    result = _require_object(
        request_protection_service(
            "get_process_snapshot_page",
            {"offset": offset, "limit": limit, "sequence": sequence},
            timeout=timeout,
        ),
        "process snapshot",
    )
    if (
        type(result.get("sequence")) is not int
        or not isinstance(result.get("processes"), list)
        or type(result.get("resync_required")) is not bool
        or (result.get("next_offset") is not None and type(result.get("next_offset")) is not int)
    ):
        raise ValueError("protection service returned malformed process snapshot data")
    return result


def get_process_events(
    *, after_sequence: int, limit: int = 500, timeout: float = 5.0
) -> dict[str, Any]:
    result = _require_object(
        request_protection_service(
            "get_process_events",
            {"after_sequence": after_sequence, "limit": limit},
            timeout=timeout,
        ),
        "process event",
    )
    if (
        type(result.get("sequence")) is not int
        or not isinstance(result.get("events"), list)
        or type(result.get("resync_required")) is not bool
    ):
        raise ValueError("protection service returned malformed process event data")
    return result


def get_process_monitor_status(*, timeout: float = 5.0) -> dict[str, Any]:
    return _require_object(
        request_protection_service("get_process_monitor_status", {}, timeout=timeout),
        "process monitor status",
    )


def get_process_details(instance_id: str, *, timeout: float = 5.0) -> dict[str, Any]:
    return _require_object(
        request_protection_service(
            "get_process_details", {"instance_id": instance_id}, timeout=timeout
        ),
        "process details",
    )


def get_process_connections(*, timeout: float = 5.0) -> dict[str, Any]:
    result = _require_object(
        request_protection_service("get_process_connections", {}, timeout=timeout),
        "process connection",
    )
    if (
        not isinstance(result.get("connections"), list)
        or type(result.get("total")) is not int
        or type(result.get("truncated")) is not bool
    ):
        raise ValueError("protection service returned malformed process connection data")
    return result


def scan_process_executable(instance_id: str, *, timeout: float = 5.0) -> dict[str, Any]:
    return _require_object(
        request_protection_service(
            "scan_process_executable", {"instance_id": instance_id}, timeout=timeout
        ),
        "process executable scan",
    )


def set_process_monitor_profile(profile: str, *, timeout: float = 5.0) -> dict[str, Any]:
    if profile not in {"low", "normal", "high"}:
        raise ValueError("process sampling profile must be low, normal, or high")
    return _require_object(
        request_protection_service(
            "set_process_monitor_profile", {"profile": profile}, timeout=timeout
        ),
        "process monitor profile",
    )
