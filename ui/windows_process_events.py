"""Windows process start/stop notifications from WMI's system trace classes.

Win32_ProcessStartTrace and Win32_ProcessStopTrace are event classes in the
Win32 system-trace provider. They deliver process IDs in the event payload;
the event header PID is not used as the affected process ID.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Any, Callable


_DISP_E_EXCEPTION = 0x80020009
# wbemErrTimedout (0x80043001) is what SWbemEventSource.NextEvent actually
# returns on this host when its window closes with no process event. 0x80041069
# is retained from the previous implementation and is still asserted by
# tests/test_windows_process_events.py; it is unverified against a live
# provider, so it stays accepted rather than being dropped.
_WMI_E_TIMED_OUT = 0x80043001
_WMI_TIMEOUT_CODES = frozenset({0x80043001, 0x80041069})
_WMI_EPOCH_SECONDS = 11_644_473_600


@dataclass(frozen=True)
class SourceStatus:
    state: str
    error: str | None
    dropped_events: int
    source: str = "Win32_ProcessTrace"


def _property(event: Any, name: str) -> Any:
    try:
        return getattr(event, name)
    except (AttributeError, TypeError):
        return None


def decode_process_event(event: Any, action: str) -> dict[str, Any] | None:
    """Decode documented Win32_ProcessTrace event fields conservatively."""
    if action not in {"start", "stop"}:
        return None
    try:
        pid = int(_property(event, "ProcessID"))
        parent_pid = int(_property(event, "ParentProcessID"))
    except (TypeError, ValueError, OverflowError):
        return None
    if pid < 0 or parent_pid < 0:
        return None
    raw_time = _property(event, "TIME_CREATED")
    try:
        event_time = int(raw_time) / 10_000_000 - _WMI_EPOCH_SECONDS
    except (TypeError, ValueError, OverflowError):
        event_time = None
    return {
        "action": action,
        "pid": pid,
        "parent_pid": parent_pid,
        "name": str(_property(event, "ProcessName") or f"Process {pid}"),
        "event_time": event_time,
        "source": "Win32_ProcessTrace",
    }


def _is_wmi_timeout(exc: BaseException) -> bool:
    """True when a NextEvent() call merely expired with no event to report.

    ``SWbemEventSource.NextEvent`` raises wbemErrTimedout whenever its window
    closes without a process starting or stopping -- the normal case on an idle
    machine. pywin32 surfaces that as DISP_E_EXCEPTION with the real WBEM code
    buried in ``excepinfo[5]``, so checking ``com_error.hresult`` alone never
    matches and a benign tick gets misread as a dead subscription.
    """
    candidates: list[int] = []
    hresult = getattr(exc, "hresult", None)
    if isinstance(hresult, int):
        candidates.append(hresult & 0xFFFFFFFF)
    excepinfo = getattr(exc, "excepinfo", None)
    if isinstance(excepinfo, (tuple, list)) and len(excepinfo) >= 6:
        scode = excepinfo[5]
        if isinstance(scode, int):
            candidates.append(scode & 0xFFFFFFFF)
    if _WMI_TIMEOUT_CODES & set(candidates):
        return True
    # Some providers report the timeout only in the description text while the
    # numeric code stays DISP_E_EXCEPTION.
    if _DISP_E_EXCEPTION in candidates and isinstance(excepinfo, (tuple, list)):
        description = next(
            (part for part in excepinfo if isinstance(part, str) and "timed out" in part.lower()),
            None,
        )
        if description is not None:
            return True
    return False


def _default_wmi_factory() -> Any:
    import win32com.client

    return win32com.client.GetObject(
        r"winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2"
    )


class WindowsProcessEventSource:
    """Consume Windows process-trace notifications without child processes."""

    def __init__(
        self,
        *,
        platform_supported: bool | None = None,
        wmi_factory: Callable[[], Any] | None = None,
    ) -> None:
        self._platform_supported = os.name == "nt" if platform_supported is None else platform_supported
        self._wmi_factory = wmi_factory
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._threads: list[threading.Thread] = []
        self._callbacks: dict[str, Callable[[dict[str, Any]], None]] = {}
        self._active = 0
        self._errors: list[str] = []
        self._dropped = 0
        self._started = False

    @property
    def status(self) -> SourceStatus:
        with self._lock:
            if not self._platform_supported:
                return SourceStatus("unavailable", "Windows process trace is available only on Windows", self._dropped)
            if self._stop.is_set():
                return SourceStatus("stopped", None, self._dropped)
            if self._active == 2:
                return SourceStatus("running", None, self._dropped)
            if self._active == 1:
                return SourceStatus("degraded", "; ".join(self._errors) or None, self._dropped)
            if self._errors:
                return SourceStatus("unavailable", "; ".join(self._errors), self._dropped)
            return SourceStatus("starting" if self._started else "stopped", None, self._dropped)

    def start(
        self,
        on_start: Callable[[dict[str, Any]], None],
        on_exit: Callable[[dict[str, Any]], None],
    ) -> SourceStatus:
        with self._lock:
            if not self._platform_supported:
                return self.status
            if self._started:
                return self.status
            self._started = True
            self._stop.clear()
            self._errors.clear()
            self._active = 0
            self._callbacks = {"start": on_start, "stop": on_exit}
            self._threads = []
            for action in ("start", "stop"):
                worker = threading.Thread(
                    target=self._watch,
                    args=(action,),
                    name=f"svs-process-trace-{action}",
                    daemon=True,
                )
                self._threads.append(worker)
                worker.start()
            return SourceStatus("starting", None, self._dropped)

    def _watch(self, action: str) -> None:
        class_name = "Win32_ProcessStartTrace" if action == "start" else "Win32_ProcessStopTrace"
        counted_active = False
        initialized_com = False
        connection = None
        source = None
        event = None
        try:
            if self._wmi_factory is None:
                import pythoncom

                pythoncom.CoInitialize()
                initialized_com = True
            connection = (self._wmi_factory or _default_wmi_factory)()
            source = connection.ExecNotificationQuery(f"SELECT * FROM {class_name}")
            with self._lock:
                self._active += 1
                counted_active = True
            while not self._stop.is_set():
                try:
                    event = source.NextEvent(1000)
                except Exception as exc:
                    if self._stop.is_set():
                        break
                    if _is_wmi_timeout(exc):
                        continue
                    message = f"{class_name} subscription failed: {exc}"
                    with self._lock:
                        self._errors.append(message)
                    break
                decoded = decode_process_event(event, action)
                callback = self._callbacks.get(action)
                if decoded is None or callback is None:
                    with self._lock:
                        self._dropped += 1
                    continue
                try:
                    callback(decoded)
                except Exception:
                    with self._lock:
                        self._dropped += 1
        except Exception as exc:
            with self._lock:
                self._errors.append(f"Could not initialize {class_name}: {exc}")
        finally:
            with self._lock:
                # Only decrement after a successful subscription was counted.
                if counted_active and self._active > 0:
                    self._active -= 1
            event = None
            source = None
            connection = None
            if initialized_com:
                try:
                    import pythoncom

                    pythoncom.CoUninitialize()
                except Exception:
                    pass

    def stop(self) -> None:
        self._stop.set()
        for worker in tuple(self._threads):
            if worker is not threading.current_thread():
                worker.join(timeout=2)
        with self._lock:
            self._active = 0
            self._threads = []
            self._callbacks = {}
            self._started = False
