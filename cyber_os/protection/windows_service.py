"""Windows service host and bounded local named-pipe API for STAI Protection.

The service starts in a truthful degraded/unavailable state unless a trusted
rule-signing public key is embedded in the installed executable, the signed
rule package validates, and the minifilter communication port is connected.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
from dataclasses import dataclass
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Callable

from .rule_package import InvalidRulePackage, RulePackage
from .store import ProtectionStore


LOGGER = logging.getLogger("stai.protection.service")
PIPE_NAME = r"\\.\pipe\STAI.Protection.v1"
PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 64 * 1024
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
_SID_TEXT = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+\Z", re.IGNORECASE)
_RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
_PIPE_IO_TIMEOUT_SECONDS = 5.0
_ERROR_NO_DATA = 232


class ProtectionServiceUnavailable(RuntimeError):
    """The protection service cannot perform the requested operation."""


class PipeProtocolError(ValueError):
    """A local pipe request violated the bounded versioned protocol."""


def _to_jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_to_jsonable(item) for item in value]
    return value


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise PipeProtocolError("duplicate JSON field")
        obj[key] = value
    return obj


def _require_payload(payload: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != fields:
        raise PipeProtocolError("payload fields do not match the operation schema")
    return payload


def _require_identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise PipeProtocolError(f"{name} is invalid")
    if any(ord(character) < 32 for character in value):
        raise PipeProtocolError(f"{name} is invalid")
    return value


_EMPTY_OPERATIONS = {
    "get_status", "list_threats", "list_quarantine", "refresh_scan_profile", "get_scan_schedule"
}
_SINGLE_ID_OPERATIONS = {
    "get_scan": ("job_id",),
    "cancel_scan": ("job_id",),
    "get_triage": ("detection_id",),
    "request_triage": ("detection_id",),
    "get_agent_history": ("session_id",),
    "restore_quarantine": ("item_id",),
}
_OPERATIONS = _EMPTY_OPERATIONS | set(_SINGLE_ID_OPERATIONS) | {
    "start_scan", "send_agent_message", "set_scan_schedule"
}


def _decode_pipe_request(raw: bytes) -> Any:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_FRAME_BYTES:
        raise PipeProtocolError("request frame is empty or exceeds the size limit")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PipeProtocolError("request is not valid UTF-8 JSON") from exc


def _validate_pipe_request(request: Any) -> tuple[str, str, dict[str, Any]]:
    if not isinstance(request, dict) or set(request) != {
        "version", "request_id", "operation", "payload"
    }:
        raise PipeProtocolError("request fields do not match protocol version 1")
    if type(request["version"]) is not int or request["version"] != PROTOCOL_VERSION:
        raise PipeProtocolError("unsupported protocol version")
    request_id = request["request_id"]
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise PipeProtocolError("request ID is invalid")
    operation = request["operation"]
    if not isinstance(operation, str) or operation not in _OPERATIONS:
        raise PipeProtocolError("operation is not allowlisted")
    payload = request["payload"]
    if operation in _EMPTY_OPERATIONS:
        _require_payload(payload, set())
    elif operation in _SINGLE_ID_OPERATIONS:
        fields = _SINGLE_ID_OPERATIONS[operation]
        parsed = _require_payload(payload, set(fields))
        for field in fields:
            _require_identifier(parsed[field], field)
    elif operation == "start_scan":
        parsed = _require_payload(payload, {"scope"})
        if parsed["scope"] not in ("quick", "system"):
            raise PipeProtocolError("scan scope must be quick or system")
    elif operation == "send_agent_message":
        parsed = _require_payload(payload, {"session_id", "message", "detection_id"})
        _require_identifier(parsed["session_id"], "session_id")
        message = parsed["message"]
        if not isinstance(message, str) or not message.strip() or len(message.encode("utf-8")) > 2000:
            raise PipeProtocolError("message must contain between 1 and 2000 bytes")
        detection_id = parsed["detection_id"]
        if detection_id is not None:
            _require_identifier(detection_id, "detection_id")
    elif operation == "set_scan_schedule":
        parsed = _require_payload(payload, {"enabled", "cadence", "local_time", "days_of_week"})
        if type(parsed["enabled"]) is not bool:
            raise PipeProtocolError("enabled must be a boolean")
        if parsed["cadence"] not in ("daily", "weekly"):
            raise PipeProtocolError("cadence must be daily or weekly")
        if not isinstance(parsed["local_time"], str) or not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", parsed["local_time"]):
            raise PipeProtocolError("local_time must use HH:MM")
        days = parsed["days_of_week"]
        allowed_days = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
        if not isinstance(days, list) or any(day not in allowed_days for day in days) or len(set(days)) != len(days):
            raise PipeProtocolError("days_of_week is invalid")
        if (parsed["cadence"] == "weekly") != bool(days):
            raise PipeProtocolError("weekly schedules require days; daily schedules require none")
    return request_id, operation, payload


@dataclass(frozen=True, slots=True)
class AuthenticatedPipeClient:
    """Verified pipe identity and its short-lived token handle."""

    sid: str
    token_handle: Any

    def close(self) -> None:
        if self.token_handle is None:
            return
        try:
            import win32api

            win32api.CloseHandle(self.token_handle)
        except ImportError:
            pass


def process_pipe_request(
    raw: bytes,
    host: Any,
    caller_context: AuthenticatedPipeClient | Any | None = None,
) -> bytes:
    """Validate and dispatch one length-delimited request body."""
    request_id = ""
    try:
        request = _decode_pipe_request(raw)
        candidate_id = request.get("request_id") if isinstance(request, dict) else None
        if isinstance(candidate_id, str) and _REQUEST_ID.fullmatch(candidate_id):
            request_id = candidate_id
        request_id, operation, payload = _validate_pipe_request(request)
        data = host.dispatch(operation, payload, caller_context=caller_context)
        response = {
            "version": PROTOCOL_VERSION,
            "request_id": request_id,
            "ok": True,
            "data": _to_jsonable(data),
        }
    except PipeProtocolError as exc:
        response = {
            "version": PROTOCOL_VERSION,
            "request_id": request_id,
            "ok": False,
            "error": str(exc),
        }
    except (LookupError, ProtectionServiceUnavailable) as exc:
        response = {
            "version": PROTOCOL_VERSION,
            "request_id": request_id,
            "ok": False,
            "error": str(exc),
        }
    except Exception:
        LOGGER.exception("protection pipe request failed")
        response = {
            "version": PROTOCOL_VERSION,
            "request_id": request_id,
            "ok": False,
            "error": "protection request failed",
        }
    try:
        encoded = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        encoded = b'{"version":1,"request_id":"","ok":false,"error":"response encoding failed"}'
    if len(encoded) > MAX_FRAME_BYTES:
        encoded = json.dumps(
            {
                "version": PROTOCOL_VERSION,
                "request_id": request_id,
                "ok": False,
                "error": "protection response exceeds the size limit",
            },
            separators=(",", ":"),
        ).encode("utf-8")
    return encoded


def _valid_sid_text(sid: str) -> bool:
    return isinstance(sid, str) and len(sid) <= 184 and bool(_SID_TEXT.fullmatch(sid))


def build_pipe_sddl(client_sid: str) -> str:
    """Grant pipe access only to SYSTEM, local administrators, and one user SID."""
    if not _valid_sid_text(client_sid):
        raise ValueError("a valid installed client SID is required")
    return f"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{client_sid})"


def is_allowed_pipe_client(client_sid: str, installed_client_sid: str) -> bool:
    if not _valid_sid_text(client_sid) or not _valid_sid_text(installed_client_sid):
        return False
    return client_sid.casefold() in {
        installed_client_sid.casefold(),
        "S-1-5-18",  # LocalSystem, for machine administration.
        "S-1-5-32-544",  # Built-in Administrators.
    }


class WindowsNamedPipeServer:
    """Single-request-per-connection server for the bounded local bridge."""

    def __init__(
        self,
        client_sid: str,
        request_handler: Callable[[bytes], bytes],
        *,
        pipe_name: str = PIPE_NAME,
    ) -> None:
        if not _valid_sid_text(client_sid):
            raise ValueError("a valid installed client SID is required")
        self._client_sid = client_sid
        self._request_handler = request_handler
        self._pipe_name = pipe_name
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._handle_lock = threading.Lock()
        self._handle: Any = None
        self._healthy = False

    @property
    def healthy(self) -> bool:
        return self._healthy

    def start(self) -> None:
        if os.name != "nt":
            raise OSError("the protection named pipe is available only on Windows")
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._serve_forever,
            name="stai-protection-pipe",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        self._stop_event.set()
        with self._handle_lock:
            handle = self._handle
            self._handle = None
        if handle is not None:
            try:
                import win32file

                cancel = getattr(win32file, "CancelIoEx", None)
                if cancel:
                    cancel(handle, None)
                win32file.CloseHandle(handle)
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._healthy = False

    def _serve_forever(self) -> None:
        import pywintypes
        import win32file
        import win32pipe
        import win32security

        while not self._stop_event.is_set():
            handle = None
            connected = False
            descriptor = None
            try:
                descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                    build_pipe_sddl(self._client_sid), win32security.SDDL_REVISION_1
                )
                attributes = pywintypes.SECURITY_ATTRIBUTES()
                attributes.SECURITY_DESCRIPTOR = descriptor
                attributes.bInheritHandle = False
                handle = win32pipe.CreateNamedPipe(
                    self._pipe_name,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    (
                        win32pipe.PIPE_TYPE_BYTE
                        | win32pipe.PIPE_READMODE_BYTE
                        | win32pipe.PIPE_WAIT
                        | win32pipe.PIPE_REJECT_REMOTE_CLIENTS
                    ),
                    1,
                    MAX_FRAME_BYTES + 4,
                    MAX_FRAME_BYTES + 4,
                    1000,
                    attributes,
                )
                with self._handle_lock:
                    self._handle = handle
                self._healthy = True
                try:
                    win32pipe.ConnectNamedPipe(handle, None)
                    connected = True
                except pywintypes.error as exc:
                    if getattr(exc, "winerror", None) == 535:  # ERROR_PIPE_CONNECTED
                        connected = True
                    elif self._stop_event.is_set():
                        break
                    else:
                        raise
                if not connected or self._stop_event.is_set():
                    continue
                win32pipe.SetNamedPipeHandleState(
                    handle, win32pipe.PIPE_NOWAIT, None, None
                )
                frame_deadline = time.monotonic() + _PIPE_IO_TIMEOUT_SECONDS
                # Windows binds the client's impersonation token to the last
                # message read from the pipe. Read the bounded length prefix
                # first, then verify the client before reading or dispatching
                # its request body.
                frame_header = self._read_exact(handle, 4, win32file, frame_deadline)
                caller = self._authenticated_client(handle)
                if caller is None:
                    continue
                body_size = int.from_bytes(frame_header, "little")
                try:
                    if body_size <= 0 or body_size > MAX_FRAME_BYTES:
                        response = process_pipe_request(b"", self, caller)
                    else:
                        body = self._read_exact(handle, body_size, win32file, frame_deadline)
                        response = self._request_handler(body, caller)
                finally:
                    caller.close()
                response_deadline = time.monotonic() + _PIPE_IO_TIMEOUT_SECONDS
                self._write_all(
                    handle,
                    len(response).to_bytes(4, "little") + response,
                    win32file,
                    response_deadline,
                )
                # Preserve queued response bytes until the client consumes them.
                self._flush_with_deadline(handle, win32file, response_deadline)
            except Exception:
                if not self._stop_event.is_set():
                    LOGGER.exception("protection named-pipe client failed")
                    time.sleep(0.1)
            finally:
                with self._handle_lock:
                    if self._handle is handle:
                        self._handle = None
                if handle is not None:
                    try:
                        if connected:
                            win32pipe.DisconnectNamedPipe(handle)
                    except Exception:
                        pass
                    try:
                        win32file.CloseHandle(handle)
                    except Exception:
                        pass
                if descriptor is not None:
                    try:
                        win32security.LocalFree(descriptor)
                    except Exception:
                        pass
        self._healthy = False

    def _authenticated_client(self, handle: Any) -> AuthenticatedPipeClient | None:
        import win32api
        import win32security

        token = None
        caller = None
        reverted = False
        try:
            win32security.ImpersonateNamedPipeClient(handle)
            token = win32security.OpenThreadToken(
                win32api.GetCurrentThread(), win32security.TOKEN_QUERY, True
            )
            token_sid = win32security.GetTokenInformation(
                token, win32security.TokenUser
            )[0]
            sid_text = win32security.ConvertSidToStringSid(token_sid)
            if is_allowed_pipe_client(sid_text, self._client_sid):
                caller = AuthenticatedPipeClient(sid_text, token)
                token = None
        except Exception:
            LOGGER.warning("rejected pipe client whose identity could not be verified")
            return False
        finally:
            if token is not None:
                try:
                    import win32api

                    win32api.CloseHandle(token)
                except Exception:
                    pass
            try:
                win32security.RevertToSelf()
                reverted = True
            except Exception:
                LOGGER.error("failed to revert pipe client impersonation")
        if not reverted:
            if caller is not None:
                caller.close()
            return None
        return caller

    @staticmethod
    def _read_exact(
        handle: Any,
        size: int,
        win32file: Any,
        deadline: float | None = None,
    ) -> bytes:
        deadline = deadline or (time.monotonic() + _PIPE_IO_TIMEOUT_SECONDS)
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            try:
                _status, data = win32file.ReadFile(handle, remaining)
            except Exception as exc:
                if _pipe_error_code(exc) != _ERROR_NO_DATA:
                    raise
                _wait_for_pipe_progress(deadline)
                continue
            if not data:
                _wait_for_pipe_progress(deadline)
                continue
            chunks.append(data)
            remaining -= len(data)
        return b"".join(chunks)

    @staticmethod
    def _write_all(
        handle: Any,
        data: bytes,
        win32file: Any,
        deadline: float | None = None,
    ) -> None:
        deadline = deadline or (time.monotonic() + _PIPE_IO_TIMEOUT_SECONDS)
        view = memoryview(data)
        while view:
            try:
                _status, written = win32file.WriteFile(handle, view.tobytes())
            except Exception as exc:
                if _pipe_error_code(exc) != _ERROR_NO_DATA:
                    raise
                _wait_for_pipe_progress(deadline)
                continue
            if not written:
                _wait_for_pipe_progress(deadline)
                continue
            view = view[written:]

    @staticmethod
    def _flush_with_deadline(
        handle: Any,
        win32file: Any,
        deadline: float,
    ) -> None:
        completed = threading.Event()
        failures: list[BaseException] = []

        def flush() -> None:
            try:
                win32file.FlushFileBuffers(handle)
            except BaseException as exc:
                failures.append(exc)
            finally:
                completed.set()

        threading.Thread(
            target=flush,
            name="stai-pipe-flush",
            daemon=True,
        ).start()
        if not completed.wait(max(0.0, deadline - time.monotonic())):
            raise TimeoutError("named-pipe response deadline exceeded")
        if failures:
            raise failures[0]


def _pipe_error_code(error: BaseException) -> int | None:
    code = getattr(error, "winerror", None)
    if code is None and getattr(error, "args", None):
        first = error.args[0]
        if isinstance(first, int):
            code = first
    return code


def _wait_for_pipe_progress(deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("named-pipe frame deadline exceeded")
    time.sleep(min(0.01, remaining))


class ProtectionServiceHost:
    """Owns the protection service, filter client, triage, and local pipe."""

    def __init__(
        self,
        *,
        store: ProtectionStore,
        service: Any | None,
        filter_client: Any | None = None,
        triage: Any | None = None,
        pipe_server: Any | None = None,
        rules_trusted: bool = False,
        client_sid: str | None = None,
        windows_security_reader: Callable[[], Any] | None = None,
        health_refresh_seconds: float = 60.0,
    ) -> None:
        self.store = store
        self.service = service
        self.filter_client = filter_client
        self.triage = triage
        self.rules_trusted = rules_trusted
        self.client_sid = client_sid
        self.pipe_server = pipe_server
        self._windows_security_reader = windows_security_reader
        self._health_refresh_seconds = max(1.0, health_refresh_seconds)
        self._health_stop_event = threading.Event()
        self._health_lock = threading.Lock()
        self._windows_security: Any = None
        self._health_thread: threading.Thread | None = None
        if self.pipe_server is None and client_sid:
            self.pipe_server = WindowsNamedPipeServer(client_sid, self.handle_request)
        self._stop_event = threading.Event()
        self._filter_thread: threading.Thread | None = None
        self._started = False
        self._service_state = "stopped"
        self._last_error: str | None = None

    def start(self) -> None:
        self._started = True
        self._service_state = "running"
        self._stop_event.clear()
        self._start_health_refresh()
        if not self.rules_trusted or self.service is None:
            self._last_error = "trusted rule package is unavailable"
        elif self.filter_client is not None:
            try:
                if self.filter_client.connect():
                    self._filter_thread = threading.Thread(
                        target=self._run_filter_client,
                        name="stai-protection-filter-client",
                        daemon=True,
                    )
                    self._filter_thread.start()
                else:
                    self._last_error = "minifilter communication port is unavailable"
                    self._start_filter_reconnect_loop()
            except Exception:
                LOGGER.exception("unable to connect to minifilter communication port")
                self._last_error = "minifilter communication port is unavailable"
                self._start_filter_reconnect_loop()
        else:
            self._last_error = "minifilter client is unavailable"

        if self.pipe_server is not None:
            try:
                self.pipe_server.start()
            except Exception:
                LOGGER.exception("unable to start the protection named pipe")
                self._last_error = "protection named pipe is unavailable"
        elif not self.client_sid:
            self._last_error = "installed dashboard client SID is not configured"

    def _start_filter_reconnect_loop(self) -> None:
        if self.filter_client is None or self.service is None or not self.rules_trusted:
            return
        self._filter_thread = threading.Thread(
            target=self._run_filter_client,
            name="stai-protection-filter-client",
            daemon=True,
        )
        self._filter_thread.start()

    def _run_filter_client(self) -> None:
        try:
            self.filter_client.run_until_stopped(
                self.service,
                self._stop_event,
                protection_store=self.store,
            )
        except Exception:
            LOGGER.exception("minifilter service loop stopped unexpectedly")
            self._last_error = "minifilter communication failed"

    def _start_health_refresh(self) -> None:
        if self._health_thread and self._health_thread.is_alive():
            return
        self._health_stop_event.clear()
        self._health_thread = threading.Thread(
            target=self._refresh_windows_security,
            name="stai-protection-windows-health",
            daemon=True,
        )
        self._health_thread.start()

    def _refresh_windows_security(self) -> None:
        while not self._health_stop_event.is_set():
            try:
                reader = self._windows_security_reader
                if reader is None:
                    from .windows_health import get_windows_security_status

                    reader = get_windows_security_status
                status = reader()
            except Exception:
                LOGGER.debug("Windows Security Center status query failed", exc_info=True)
                try:
                    from .windows_health import WindowsSecurityStatus

                    status = WindowsSecurityStatus(None, None, False)
                except Exception:
                    status = None
            with self._health_lock:
                self._windows_security = status
            if self._health_stop_event.wait(self._health_refresh_seconds):
                return

    def stop(self) -> None:
        self._stop_event.set()
        self._health_stop_event.set()
        if self.pipe_server is not None:
            try:
                self.pipe_server.close()
            except Exception:
                LOGGER.exception("failed to close protection named pipe")
        if self.triage is not None:
            try:
                self.triage.close()
            except Exception:
                LOGGER.exception("failed to close protection triage workers")
        if self.filter_client is not None:
            try:
                self.filter_client.close()
            except Exception:
                LOGGER.exception("failed to close minifilter client")
        if self._filter_thread and self._filter_thread.is_alive():
            self._filter_thread.join(timeout=6)
        if self._health_thread and self._health_thread.is_alive():
            self._health_thread.join(timeout=2)
        self._started = False
        self._service_state = "stopped"

    def get_status(self) -> dict[str, Any]:
        connected = bool(
            getattr(
                self.filter_client,
                "connected",
                getattr(self.filter_client, "_connected", False),
            )
        )
        driver_state = "running" if connected else "stopped"
        service_state = self._service_state
        rules_version = (
            self.service.rules.version
            if self.rules_trusted and self.service is not None
            else "unknown"
        )
        with self._health_lock:
            windows_security = self._windows_security
        if self.service is not None:
            status = self.service.get_status(
                driver_state=driver_state,
                service_state=service_state,
                windows_security=windows_security,
                last_error=self._last_error,
            )
        else:
            status = self.store.get_status(
                driver_state=driver_state,
                service_state=service_state,
                rules_version=rules_version,
                windows_security=windows_security,
                last_error=self._last_error,
            )
        result = _to_jsonable(status)
        if not isinstance(result, dict):
            result = {}
        result.update(
            driver_state=driver_state,
            service_state=service_state,
            rules_version=rules_version,
            state=(
                "active"
                if self._started and self.service is not None and self.rules_trusted and connected
                else "unavailable"
                if self.service is None or not self.rules_trusted
                else "degraded"
            ),
        )
        if self._last_error:
            result["last_error"] = self._last_error
        return result

    def handle_request(
        self,
        body: bytes,
        caller_context: AuthenticatedPipeClient | None = None,
    ) -> bytes:
        return process_pipe_request(body, self, caller_context)

    def dispatch(
        self,
        operation: str,
        payload: dict[str, Any],
        *,
        caller_context: AuthenticatedPipeClient | None = None,
    ) -> Any:
        if operation == "get_status":
            return self.get_status()
        if operation == "list_threats":
            return self.store.list_threats(limit=500)
        if operation == "list_quarantine":
            from .quarantine import list_quarantine_items

            return list_quarantine_items(self.store)
        if operation == "get_scan":
            job = self.store.get_scan_job(payload["job_id"])
            if job is None:
                raise LookupError("scan job not found")
            return job
        if operation in ("get_triage", "request_triage"):
            if self.triage is None:
                raise ProtectionServiceUnavailable("protection triage is unavailable")
            detection_id = payload["detection_id"]
            record = (
                self.triage.get(detection_id)
                if operation == "get_triage"
                else self.triage.request(detection_id)
            )
            if record is None:
                raise LookupError("triage result not found")
            triage = _to_jsonable(record)
            return {
                "triage_id": triage.get("detection_id", detection_id),
                "detection_id": detection_id,
                "summary": triage.get("summary"),
                "recommendations": [],
                "state": triage.get("status", triage.get("state", "unavailable")),
                "error": triage.get("error"),
                "created_at": triage.get("created_at"),
                "updated_at": triage.get("updated_at"),
            }
        if operation == "get_agent_history":
            if self.triage is None:
                raise ProtectionServiceUnavailable("protection triage is unavailable")
            session_id = payload["session_id"]
            messages = self.triage.history(session_id)
            return {"session_id": session_id, "messages": messages}
        if operation == "send_agent_message":
            if self.triage is None:
                raise ProtectionServiceUnavailable("protection triage is unavailable")
            return self.triage.send_message(
                session_id=payload["session_id"],
                message=payload["message"],
                detection_id=payload["detection_id"],
            )
        if operation in {"refresh_scan_profile", "get_scan_schedule", "set_scan_schedule"}:
            self._require_enrolled_caller(caller_context)
            if operation == "get_scan_schedule":
                return self._schedule_response(self.store.get_scan_schedule(self.client_sid))
            if operation == "set_scan_schedule":
                schedule = self.store.set_scan_schedule(
                    self.client_sid,
                    enabled=payload["enabled"],
                    cadence=payload["cadence"],
                    local_time=payload["local_time"],
                    days_of_week=tuple(payload["days_of_week"]),
                )
                return self._schedule_response(schedule)
            if self.service is None or not self.rules_trusted:
                raise ProtectionServiceUnavailable("protection service is unavailable")
            profile = self.service.refresh_scan_profile(
                self.client_sid,
                caller_context.token_handle,
            )
            return {
                "ready": True,
                "refreshed_at": profile.refreshed_at,
                "folders": [folder_id for folder_id, _path in profile.roots],
            }
        if self.service is None or not self.rules_trusted:
            raise ProtectionServiceUnavailable("protection service is unavailable")
        if operation == "start_scan":
            return self.service.start_scan(payload["scope"])
        if operation == "cancel_scan":
            job_id = payload["job_id"]
            self.service.cancel_scan(job_id)
            job = self.store.get_scan_job(job_id)
            if job is None:
                raise LookupError("scan job not found")
            return job
        if operation == "restore_quarantine":
            result = self.service.restore_quarantine(payload["item_id"])
            return _to_jsonable(result)
        raise PipeProtocolError("operation is not allowlisted")

    def _require_enrolled_caller(self, caller_context: AuthenticatedPipeClient | None) -> None:
        if (
            caller_context is None
            or not self.client_sid
            or caller_context.sid.casefold() != self.client_sid.casefold()
        ):
            raise ProtectionServiceUnavailable("operation requires the enrolled dashboard user")

    @staticmethod
    def _schedule_response(schedule: Any | None) -> dict[str, Any]:
        if schedule is None:
            return {"enabled": False, "configured": False}
        result = _to_jsonable(schedule)
        if not isinstance(result, dict):
            return {"enabled": False, "configured": False}
        result["configured"] = True
        return result


def _read_installed_client_sid() -> str | None:
    if os.name != "nt":
        return None
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\STAI\Protection",
            0,
            winreg.KEY_READ,
        ) as key:
            sid, _kind = winreg.QueryValueEx(key, "DashboardClientSid")
        return sid if _valid_sid_text(sid) else None
    except (OSError, ImportError):
        return None


def create_default_host() -> ProtectionServiceHost:
    """Build a host only from installed data and the embedded trusted public key."""
    data_root = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "STAI" / "Protection"
    store = ProtectionStore(data_root / "protection.db")
    rules = None
    last_error = None
    public_key_path = _RESOURCE_ROOT / "resources" / "trusted-rules.pub"
    manifest_path = data_root / "rules" / "manifest.json"
    signature_path = data_root / "rules" / "manifest.sig"
    try:
        public_key = public_key_path.read_bytes()
        if len(public_key) != 32:
            raise InvalidRulePackage("embedded trusted public key has invalid length")
        rules = RulePackage.load(manifest_path, signature_path, public_key)
    except (OSError, InvalidRulePackage):
        last_error = "trusted rule package is unavailable or invalid"

    service = None
    from .ai_provider import create_default_provider
    from .triage import ProtectionTriage

    triage = ProtectionTriage(store, create_default_provider())
    if rules is not None:
        from .service import ProtectionConfig, ProtectionService

        service = ProtectionService(
            ProtectionConfig(
                quarantine_root=data_root / "quarantine",
                rules=rules,
                store=store,
            ),
            on_detection=triage.request,
        )

    filter_client = None
    if os.name == "nt":
        from .filter_client import create_filter_client

        filter_client = create_filter_client()

    client_sid = _read_installed_client_sid()
    host = ProtectionServiceHost(
        store=store,
        service=service,
        filter_client=filter_client,
        triage=triage,
        rules_trusted=rules is not None,
        client_sid=client_sid,
    )
    if last_error:
        host._last_error = last_error
    return host


try:
    import win32service
    import win32serviceutil
    import win32event
    import win32timezone  # noqa: F401  # required for frozen pywin32 services
except ImportError:  # Keep protocol and status code importable on non-Windows hosts.
    win32service = None
    win32serviceutil = None
    win32event = None


if win32serviceutil is not None:
    class STAIProtectionWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "STAIProtection"
        _svc_display_name_ = "STAI Windows Protection Service"
        _svc_description_ = "Runs the local STAI protection engine and dashboard bridge."

        def __init__(self, args: Any) -> None:
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._host: ProtectionServiceHost | None = None

        def SvcStop(self) -> None:  # noqa: N802 - pywin32 callback name
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)
            if self._host is not None:
                self._host.stop()

        def SvcDoRun(self) -> None:  # noqa: N802 - pywin32 callback name
            try:
                self._host = create_default_host()
                self._host.start()
                win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
            except Exception:
                LOGGER.exception("STAI protection service failed to start")
                raise
            finally:
                if self._host is not None:
                    self._host.stop()


def main() -> None:
    if win32serviceutil is None:
        raise RuntimeError("pywin32 is required to run STAI Protection as a Windows service")
    win32serviceutil.HandleCommandLine(STAIProtectionWindowsService)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
