"""Resolve the enrolled Windows user's fixed scan folders."""

from __future__ import annotations

import ctypes
import ntpath
import uuid
from ctypes import wintypes
from typing import Callable


KNOWN_FOLDER_GUIDS = {
    "desktop": "B4BFCC3A-DB2C-424C-B029-7FE99A87C641",
    "downloads": "374DE290-123F-4565-9164-39C4925E467B",
    "startup": "B97D20BB-F46A-4C97-BA10-5E3608430854",
}
KNOWN_FOLDER_IDS = ("desktop", "downloads", "startup")


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_text(cls, text: str) -> "_GUID":
        value = uuid.UUID(text)
        # UUID.node is 48 bits. Preserve all six node bytes in GUID order.
        data4 = bytes((value.clock_seq_hi_variant, value.clock_seq_low)) + value.node.to_bytes(6, "big")
        return cls(value.time_low, value.time_mid, value.time_hi_version, (ctypes.c_ubyte * 8).from_buffer_copy(data4))


def _token_handle_value(token_handle: object) -> int:
    try:
        return int(token_handle)
    except (TypeError, ValueError):
        value = getattr(token_handle, "handle", None)
        if value is None:
            raise ValueError("a Windows user token is required")
        return int(value)


def _resolve_known_folder(folder_id: str, token_handle: object) -> str:
    if folder_id not in KNOWN_FOLDER_GUIDS:
        raise ValueError("known-folder ID is not allowlisted")
    if not hasattr(ctypes, "WinDLL"):
        raise OSError("Windows known folders are unavailable on this platform")

    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    ole32 = ctypes.WinDLL("ole32", use_last_error=True)
    get_folder = shell32.SHGetKnownFolderPath
    get_folder.argtypes = [
        ctypes.POINTER(_GUID),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    get_folder.restype = ctypes.c_long
    free_memory = ole32.CoTaskMemFree
    free_memory.argtypes = [ctypes.c_void_p]
    free_memory.restype = None

    folder_guid = _GUID.from_text(KNOWN_FOLDER_GUIDS[folder_id])
    path_pointer = ctypes.c_wchar_p()
    result = get_folder(
        ctypes.byref(folder_guid),
        0,
        wintypes.HANDLE(_token_handle_value(token_handle)),
        ctypes.byref(path_pointer),
    )
    if result != 0:
        raise OSError(result, f"Windows could not resolve the {folder_id} folder")
    try:
        return path_pointer.value or ""
    finally:
        if path_pointer:
            free_memory(ctypes.cast(path_pointer, ctypes.c_void_p))


class KnownFolderResolver:
    """Resolve and normalize only Desktop, Downloads, and Startup."""

    def __init__(
        self,
        resolve_folder: Callable[[str, object], str] | None = None,
    ) -> None:
        self._resolve_folder = resolve_folder or _resolve_known_folder

    def resolve(self, token_handle: object) -> tuple[tuple[str, str], ...]:
        if token_handle is None:
            raise ValueError("authenticated Windows user token is required")
        roots: list[tuple[str, str]] = []
        for folder_id in KNOWN_FOLDER_IDS:
            try:
                raw_path = self._resolve_folder(folder_id, token_handle)
            except Exception as exc:
                raise OSError(f"could not resolve the {folder_id} known folder") from exc
            if not isinstance(raw_path, str) or not raw_path.strip():
                raise OSError(f"Windows returned no path for {folder_id}")
            canonical = ntpath.normpath(raw_path.strip())
            if not ntpath.isabs(canonical):
                raise OSError(f"Windows returned a non-absolute path for {folder_id}")
            roots.append((folder_id, canonical))
        return tuple(roots)
