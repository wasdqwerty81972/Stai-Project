"""FltLib wrapper for Filter Manager communication port."""

from __future__ import annotations

import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

from .filter_protocol import (
    FilterCompletion,
    FilterReply,
    FilterRequest,
    decode_filter_completion,
    decode_filter_reply,
    decode_filter_request,
    encode_filter_completion,
    encode_filter_reply,
    encode_filter_request,
)
from .models import ScanVerdict


FAIL_OPEN_RULE_VERSION = "unknown"


def fail_open_verdict(
    reason: str = "service unavailable",
    rule_version: str = FAIL_OPEN_RULE_VERSION,
) -> ScanVerdict:
    """Return the safe fail-open verdict, which never blocks.

    Used whenever the service cannot produce a confident verdict (scan
    error/timeout, disconnected or unavailable port, malformed frame). The
    status is ``unknown`` and the action is ``allow`` so the kernel allows the
    operation and the UI reports degraded protection. Only a verified
    high-confidence block verdict may deny I/O.
    """
    return ScanVerdict(
        status="unknown",
        action="allow",
        rule_id=None,
        rule_version=rule_version,
        sha256=None,
        reason=reason,
    )


@dataclass(slots=True)
class FilterClientConfig:
    port_name: str = r"\\.\STAIProtectionPort"
    timeout_ms: int = 5000


class NativeFilterClient(ABC):
    """Abstract base for native Filter Manager communication."""
    
    @abstractmethod
    def connect(self, port_name: str, timeout_ms: int) -> bool:
        pass
    
    @abstractmethod
    def receive(self, timeout_ms: int) -> Optional[bytes]:
        pass
    
    @abstractmethod
    def send(self, data: bytes) -> bool:
        pass
    
    @abstractmethod
    def close(self) -> None:
        pass


class WindowsNativeClient(NativeFilterClient):
    """Windows implementation using FltLib via ctypes."""
    
    def __init__(self) -> None:
        self._handle: Any = None
        self._fltlib: Any = None
        self._load_fltlib()
    
    def _load_fltlib(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("FltLib is only available on Windows")
        try:
            import ctypes
            from ctypes import wintypes
            self._fltlib = ctypes.WinDLL("fltlib.dll")
            
            # FilterConnectCommunicationPort
            self._fltlib.FilterConnectCommunicationPort.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.WORD,
                wintypes.LPVOID,
                ctypes.POINTER(wintypes.HANDLE),
            ]
            self._fltlib.FilterConnectCommunicationPort.restype = wintypes.HRESULT
            
            # FilterSendMessage
            self._fltlib.FilterSendMessage.argtypes = [
                wintypes.HANDLE,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            self._fltlib.FilterSendMessage.restype = wintypes.HRESULT
            
            # FilterGetMessage
            self._fltlib.FilterGetMessage.argtypes = [
                wintypes.HANDLE,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            self._fltlib.FilterGetMessage.restype = wintypes.HRESULT
            
            # FilterCloseCommunicationPort
            self._fltlib.FilterCloseCommunicationPort.argtypes = [wintypes.HANDLE]
            self._fltlib.FilterCloseCommunicationPort.restype = wintypes.HRESULT
            
        except (OSError, AttributeError):
            self._fltlib = None
    
    def connect(self, port_name: str, timeout_ms: int) -> bool:
        if not self._fltlib:
            return False
        
        import ctypes
        from ctypes import wintypes
        
        handle = wintypes.HANDLE()
        hr = self._fltlib.FilterConnectCommunicationPort(
            port_name,
            0,
            None,
            0,
            None,
            ctypes.byref(handle),
        )
        
        if hr >= 0:
            self._handle = handle
            return True
        return False
    
    def receive(self, timeout_ms: int) -> Optional[bytes]:
        if not self._fltlib or not self._handle:
            return None
        
        import ctypes
        from ctypes import wintypes
        
        # First get the message size
        buffer_size = wintypes.DWORD(0)
        hr = self._fltlib.FilterGetMessage(
            self._handle,
            None,
            0,
            None,
            0,
            ctypes.byref(buffer_size),
        )
        
        if hr == 0x8007007A:  # HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)
            # Allocate buffer and get the message
            buffer = ctypes.create_string_buffer(buffer_size.value)
            bytes_returned = wintypes.DWORD(0)
            hr = self._fltlib.FilterGetMessage(
                self._handle,
                buffer,
                buffer_size,
                None,
                0,
                ctypes.byref(bytes_returned),
            )
            if hr >= 0:
                return bytes(buffer[:bytes_returned.value])
        
        return None
    
    def send(self, data: bytes) -> bool:
        if not self._fltlib or not self._handle:
            return False
        
        import ctypes
        from ctypes import wintypes
        
        buffer = ctypes.create_string_buffer(data)
        bytes_returned = wintypes.DWORD(0)
        hr = self._fltlib.FilterSendMessage(
            self._handle,
            buffer,
            len(data),
            None,
            0,
            ctypes.byref(bytes_returned),
        )
        
        return hr >= 0
    
    def close(self) -> None:
        if self._fltlib and self._handle:
            self._fltlib.FilterCloseCommunicationPort(self._handle)
            self._handle = None


class FilterClient:
    """High-level client for STAI minifilter communication."""
    
    def __init__(
        self,
        config: Optional[FilterClientConfig] = None,
        native_client: Optional[NativeFilterClient] = None,
    ) -> None:
        self._config = config or FilterClientConfig()
        self._native = native_client
        self._connected = False
        self._protection_store: Any = None
    
    def set_protection_store(self, store: Any) -> None:
        """Set the protection store for recording completions."""
        self._protection_store = store
    
    def connect(self) -> bool:
        if self._connected:
            return True
        
        # Try to create native client if not provided
        if self._native is None:
            try:
                self._native = WindowsNativeClient()
            except RuntimeError:
                return False
        
        if self._native is None:
            return False
        
        self._connected = self._native.connect(self._config.port_name, self._config.timeout_ms)
        return self._connected
    
    def receive(self) -> Optional[FilterRequest]:
        if not self._connected or not self._native:
            return None
        
        data = self._native.receive(self._config.timeout_ms)
        if data is None:
            return None
        
        try:
            return decode_filter_request(data)
        except Exception:
            return None
    
    def reply(self, request_id: int, verdict: ScanVerdict) -> None:
        if not self._connected or not self._native:
            return
        
        reply = FilterReply(request_id=request_id, verdict=verdict)
        encoded = encode_filter_reply(reply)
        self._native.send(encoded)

    def reply_fail_open(self, request_id: int, reason: str = "service unavailable") -> None:
        """Reply with the safe fail-open (allow/unknown) verdict for a request.

        A no-op when the port is not connected, so a disconnected service never
        emits a block and the kernel independently fails open.
        """
        self.reply(request_id, fail_open_verdict(reason))
    
    def send_completion(self, completion: FilterCompletion) -> None:
        """Send completion frame and record blocked count if access was denied."""
        if not self._connected or not self._native:
            return
        
        encoded = encode_filter_completion(completion)
        self._native.send(encoded)
        
        # Record in protection store if available
        if self._protection_store and hasattr(self._protection_store, 'record_filter_completion'):
            # Only increment blocked for STATUS_ACCESS_DENIED
            if completion.final_io_status == "STATUS_ACCESS_DENIED":
                self._protection_store.record_filter_completion(
                    str(completion.request_id),
                    completion.final_io_status
                )
    
    def close(self) -> None:
        if self._native:
            self._native.close()
        self._connected = False


class MockFilterClient(FilterClient):
    """Mock client for testing on non-Windows platforms."""
    
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._queue: list[FilterRequest] = []
        self._replies: dict[int, FilterReply] = {}
        self._completions: list[FilterCompletion] = []
    
    def connect(self) -> bool:
        self._connected = True
        return True
    
    def receive(self) -> Optional[FilterRequest]:
        if self._queue:
            return self._queue.pop(0)
        return None
    
    def reply(self, request_id: int, verdict: ScanVerdict) -> None:
        self._replies[request_id] = FilterReply(request_id=request_id, verdict=verdict)
    
    def send_completion(self, completion: FilterCompletion) -> None:
        self._completions.append(completion)
        if self._protection_store and hasattr(self._protection_store, 'record_filter_completion'):
            if completion.final_io_status == "STATUS_ACCESS_DENIED":
                self._protection_store.record_filter_completion(
                    str(completion.request_id),
                    completion.final_io_status
                )
    
    def close(self) -> None:
        self._connected = False
    
    def inject_request(self, request: FilterRequest) -> None:
        self._queue.append(request)
    
    def get_last_reply(self, request_id: int) -> Optional[FilterReply]:
        return self._replies.get(request_id)
    
    def get_completions(self) -> list[FilterCompletion]:
        return self._completions.copy()


def create_filter_client(
    config: Optional[FilterClientConfig] = None,
    native_client: Optional[NativeFilterClient] = None,
) -> FilterClient:
    """Factory function to create the appropriate client for the platform."""
    if sys.platform == "win32":
        return FilterClient(config, native_client)
    return MockFilterClient(config, native_client)