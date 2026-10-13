"""Bounded client for the authenticated local protection named pipe."""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any

from .windows_service import MAX_FRAME_BYTES, PIPE_NAME, PROTOCOL_VERSION


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
        remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
        win32pipe.WaitNamedPipe(PIPE_NAME, remaining_ms)
        handle = win32file.CreateFile(
            PIPE_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None,
        )
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
