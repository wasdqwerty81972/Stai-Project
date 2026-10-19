"""Best-effort post-write scanning for the enrolled Windows user's drop folders.

This user-mode watcher complements Windows audit events. It does not replace a
minifilter: notifications arrive after filesystem changes and cover only the
configured directories.
"""

from __future__ import annotations

import ctypes
import os
import platform
import re
import stat
import struct
import threading
import uuid
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from cyber_os.sensors.windows_sensor_service import SensorEvent


FILE_ACTION_ADDED = 1
FILE_ACTION_REMOVED = 2
FILE_ACTION_MODIFIED = 3
FILE_ACTION_RENAMED_OLD_NAME = 4
FILE_ACTION_RENAMED_NEW_NAME = 5

_FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
_FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
_FILE_NOTIFY_CHANGE_SIZE = 0x00000008
_FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
_FILE_LIST_DIRECTORY = 0x0001
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OVERLAPPED = 0x40000000
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_WAIT_INTERVAL_MS = 250
_BUFFER_SIZE = 64 * 1024
_MAX_PENDING_FILES = 512
_SCAN_ACTIONS = {FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_RENAMED_NEW_NAME}
_EXECUTABLE_SUFFIXES = {".exe", ".dll", ".sys", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi"}
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def parse_file_notify_buffer(raw: bytes) -> list[tuple[int, str]]:
    """Parse the linked FILE_NOTIFY_INFORMATION records returned by Win32."""
    changes: list[tuple[int, str]] = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 12:
            raise ValueError("truncated FILE_NOTIFY_INFORMATION header")
        next_offset, action, name_bytes = struct.unpack_from("<III", raw, offset)
        name_start = offset + 12
        name_end = name_start + name_bytes
        if name_bytes % 2 or name_end > len(raw):
            raise ValueError("invalid FILE_NOTIFY_INFORMATION filename length")
        try:
            name = raw[name_start:name_end].decode("utf-16-le")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid FILE_NOTIFY_INFORMATION filename") from exc
        changes.append((action, name))
        if next_offset == 0:
            break
        if next_offset < 12 or offset + next_offset > len(raw):
            raise ValueError("invalid FILE_NOTIFY_INFORMATION next offset")
        offset += next_offset
    return changes


def monitored_user_roots(profile_root: Path, known_folders: dict[str, str] | None = None) -> list[Path]:
    """Return existing drop folders, honoring enrolled-user folder redirection."""
    profile = Path(profile_root)
    known_folders = known_folders or {}

    def resolve_folder(value: str, fallback: Path) -> Path:
        if not value:
            return fallback
        expanded = re.sub(r"%USERPROFILE%", lambda _match: str(profile), value, flags=re.IGNORECASE)
        expanded = re.sub(
            r"%LOCALAPPDATA%", lambda _match: str(profile / "AppData" / "Local"), expanded, flags=re.IGNORECASE
        )
        expanded = re.sub(
            r"%APPDATA%", lambda _match: str(profile / "AppData" / "Roaming"), expanded, flags=re.IGNORECASE
        )
        return Path(os.path.expandvars(expanded)).expanduser()

    candidates = (
        resolve_folder(known_folders.get("Downloads", ""), profile / "Downloads"),
        resolve_folder(known_folders.get("Desktop", ""), profile / "Desktop"),
        profile / "AppData" / "Local" / "Temp",
    )
    output: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        try:
            canonical = path.resolve()
            key = os.path.normcase(str(canonical))
            if (
                canonical.is_dir()
                and not str(canonical).startswith("\\\\")
                and not path.is_symlink()
                and key not in seen
            ):
                output.append(canonical)
                seen.add(key)
        except OSError:
            continue
    return output


def build_file_activity_event(path: Path, action: int) -> SensorEvent | None:
    """Create a privacy-filtered event for an added, renamed, or modified file."""
    if action not in _SCAN_ACTIONS:
        return None
    target = Path(path)
    try:
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
            return None
    except OSError:
        return None
    suffix = target.suffix.casefold()
    summary = (
        f"An executable or script was written to a monitored folder ({suffix or 'no extension'})."
        if suffix in _EXECUTABLE_SUFFIXES
        else "A file was written to a monitored folder; content scanning is pending."
    )
    return SensorEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_id=f"drop:{uuid.uuid4().hex}",
        event_type="file_activity",
        category="file",
        severity="INFO",
        source="Windows directory change notification",
        details={"file_operation": "create_or_modify", "summary": summary},
        capabilities=["File Creation", "File Modification"],
        sensor_ids=[49, 50],
        _protection_target=str(target),
    )


class WindowsFileActivityMonitor:
    """Watch selected enrolled-user folders and forward stable file changes."""

    def __init__(
        self,
        roots: list[Path],
        callback: Callable[[SensorEvent], None],
        *,
        settle_seconds: float = 0.8,
        deduplicator: "SensorEventDeduplicator | None" = None,
    ):
        self.roots = [Path(root) for root in roots]
        self.callback = callback
        # Pass the same instance given to WindowsSensorService so a file write
        # seen by both this watcher and Security event 4663 is reported once.
        self.deduplicator = deduplicator
        self.settle_seconds = max(0.1, min(5.0, settle_seconds))
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._threads: list[threading.Thread] = []
        self._timers: dict[str, threading.Timer] = {}
        self._errors: dict[str, str] = {}
        self._running = False
        self.suppressed_duplicates = 0

    def start(self) -> bool:
        if platform.system() != "Windows" or not self.roots:
            return False
        with self._lock:
            if self._running:
                return False
            self._stop.clear()
            self._errors.clear()
            self._threads = [
                threading.Thread(target=self._watch_root, args=(root,), daemon=True, name="STAIFileWatch")
                for root in self.roots
            ]
            self._running = True
            for thread in self._threads:
                thread.start()
            return True

    def stop(self, timeout: float = 5.0) -> bool:
        self._stop.set()
        with self._lock:
            timers = list(self._timers.values())
            self._timers.clear()
            threads = list(self._threads)
        for timer in timers:
            timer.cancel()
        for thread in threads:
            thread.join(timeout=max(0.0, timeout))
        stopped = not any(thread.is_alive() for thread in threads)
        with self._lock:
            self._running = not stopped
        return stopped

    def get_status(self) -> dict[str, object]:
        with self._lock:
            running = self._running and any(thread.is_alive() for thread in self._threads)
            return {
                "state": "running" if running else "error" if self._errors else "unavailable",
                "roots": [str(root) for root in self.roots],
                "active_roots": sum(thread.is_alive() for thread in self._threads),
                "errors": dict(self._errors),
                "coverage": "post_write_selected_user_folders",
            }

    def _watch_root(self, root: Path) -> None:
        handle = event_handle = None
        try:
            if platform.system() != "Windows":
                raise OSError("Windows directory notifications are only available on Windows")
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle, event_handle, overlapped, buffer = _open_directory_watch(kernel32, root)
            kernel32.ReadDirectoryChangesW.argtypes = [
                wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.BOOL,
                wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, ctypes.c_void_p,
            ]
            kernel32.ReadDirectoryChangesW.restype = wintypes.BOOL
            kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel32.WaitForSingleObject.restype = wintypes.DWORD
            kernel32.GetOverlappedResult.argtypes = [
                wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
            ]
            kernel32.GetOverlappedResult.restype = wintypes.BOOL
            kernel32.ResetEvent.argtypes = [wintypes.HANDLE]
            kernel32.ResetEvent.restype = wintypes.BOOL
            kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
            kernel32.CancelIoEx.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            while not self._stop.is_set():
                if not kernel32.ReadDirectoryChangesW(
                    handle, ctypes.byref(buffer), _BUFFER_SIZE, True,
                    _FILE_NOTIFY_CHANGE_FILE_NAME | _FILE_NOTIFY_CHANGE_DIR_NAME | _FILE_NOTIFY_CHANGE_SIZE | _FILE_NOTIFY_CHANGE_LAST_WRITE,
                    None, ctypes.byref(overlapped), None,
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
                while not self._stop.is_set():
                    result = kernel32.WaitForSingleObject(event_handle, _WAIT_INTERVAL_MS)
                    if result == _WAIT_TIMEOUT:
                        continue
                    if result != _WAIT_OBJECT_0:
                        raise ctypes.WinError(ctypes.get_last_error())
                    transferred = wintypes.DWORD()
                    if not kernel32.GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(transferred), False):
                        error = ctypes.get_last_error()
                        if error == 995 and self._stop.is_set():
                            return
                        raise ctypes.WinError(error)
                    if transferred.value == 0:
                        with self._lock:
                            self._errors[str(root)] = "directory notification buffer overflow; some changes may have been missed"
                    else:
                        for action, relative_name in parse_file_notify_buffer(buffer.raw[:transferred.value]):
                            if action in _SCAN_ACTIONS:
                                path = root / relative_name
                                try:
                                    if not path.resolve(strict=False).is_relative_to(root.resolve()):
                                        continue
                                except OSError:
                                    continue
                                self._queue_scan(path, action)
                    kernel32.ResetEvent(event_handle)
                    overlapped.Internal = 0
                    overlapped.InternalHigh = 0
                    overlapped.Offset = 0
                    overlapped.OffsetHigh = 0
                    break
        except Exception as exc:
            with self._lock:
                self._errors[str(root)] = str(exc)[:240]
        finally:
            if handle:
                if self._stop.is_set():
                    try:
                        kernel32.CancelIoEx(handle, ctypes.byref(overlapped))
                    except Exception:
                        pass
                kernel32.CloseHandle(handle)
            if event_handle:
                kernel32.CloseHandle(event_handle)

    def _queue_scan(self, path: Path, action: int) -> None:
        key = os.path.normcase(os.path.abspath(path))
        with self._lock:
            previous = self._timers.pop(key, None)
            if previous:
                previous.cancel()
            elif len(self._timers) >= _MAX_PENDING_FILES:
                self._errors[str(path.parent)] = "pending scan limit reached; file notifications are being dropped"
                return
            timer = threading.Timer(self.settle_seconds, self._dispatch, args=(key, path, action))
            timer.daemon = True
            self._timers[key] = timer
            timer.start()

    def _dispatch(self, key: str, path: Path, action: int) -> None:
        with self._lock:
            self._timers.pop(key, None)
        if self._stop.is_set():
            return
        event = build_file_activity_event(path, action)
        if event is not None:
            try:
                self.callback(event)
            except Exception as exc:
                with self._lock:
                    self._errors[str(path.parent)] = f"scan callback failed: {exc}"[:240]


def _open_directory_watch(kernel32: object, root: Path):
    """Open an overlapped directory handle and allocate notification state."""
    class Overlapped(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    invalid = ctypes.c_void_p(-1).value
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(root), _FILE_LIST_DIRECTORY,
        _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
        None, _OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OVERLAPPED, None,
    )
    if handle == invalid:
        raise ctypes.WinError(ctypes.get_last_error())
    create_event = kernel32.CreateEventW
    create_event.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    create_event.restype = wintypes.HANDLE
    event_handle = create_event(None, True, False, None)
    if not event_handle:
        kernel32.CloseHandle(handle)
        raise ctypes.WinError(ctypes.get_last_error())
    overlapped = Overlapped()
    overlapped.hEvent = event_handle
    buffer = ctypes.create_string_buffer(_BUFFER_SIZE)
    return handle, event_handle, overlapped, buffer
