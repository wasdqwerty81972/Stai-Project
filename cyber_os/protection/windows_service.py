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
from datetime import datetime, timezone
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Callable

from .rule_package import InvalidRulePackage, RulePackage, rule_set_fingerprint
from .store import ProtectionStore, ThreatIntelStore


LOGGER = logging.getLogger("stai.protection.service")
PIPE_NAME = r"\\.\pipe\STAI.Protection.v1"
PROTOCOL_VERSION = 1
# The system-status response includes the complete 256-entry sensor catalog
# (currently ~382 KiB). Keep the pipe bounded while allowing that dashboard
# payload to pass intact.
MAX_FRAME_BYTES = 1024 * 1024
# Upper bound on WFP events returned by one get_network_telemetry call. The
# response must fit MAX_FRAME_BYTES, so a busy monitor must not be able to
# produce a frame that gets rejected wholesale as oversized.
MAX_NETWORK_TELEMETRY_EVENTS = 512
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
_PROCESS_INSTANCE_ID = re.compile(
    r"(?:[0-9]+:0x[0-9a-f]+\.[0-9a-f]+p[+-][0-9]+|unverified:[0-9]+:[0-9a-f]{32})\Z",
    re.IGNORECASE,
)
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
    "get_status", "get_rule_metadata", "get_active_scan", "get_scan_schedule", "list_threats", "list_quarantine",
    "list_sensor_warnings",
    # Network telemetry is read-only by construction: it takes no payload, so a
    # pipe client cannot smuggle a policy/enforcement parameter (e.g. "block")
    # through this operation. Enforcement stays behind the privileged paths.
    "get_network_telemetry",
    "get_process_monitor_status",
    "get_process_connections",
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
    "start_scan", "get_scan_schedule", "set_scan_schedule", "send_agent_message",
    "claim_sensor_ai_escalations", "complete_sensor_ai_escalation",
    "get_process_snapshot_page", "get_process_events", "get_process_details",
    "set_process_monitor_profile",
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
    elif operation == "get_process_snapshot_page":
        parsed = _require_payload(payload, {"offset", "limit", "sequence"})
        offset, limit, sequence = parsed["offset"], parsed["limit"], parsed["sequence"]
        if type(offset) is not int or not 0 <= offset <= 10_000_000:
            raise PipeProtocolError("process snapshot offset is invalid")
        if type(limit) is not int or not 1 <= limit <= 500:
            raise PipeProtocolError("process snapshot limit must be between 1 and 500")
        if sequence is not None and (
            type(sequence) is not int or not 0 <= sequence <= 2**63 - 1
        ):
            raise PipeProtocolError("process snapshot sequence is invalid")
    elif operation == "get_process_events":
        parsed = _require_payload(payload, {"after_sequence", "limit"})
        if type(parsed["after_sequence"]) is not int or not 0 <= parsed["after_sequence"] <= 2**63 - 1:
            raise PipeProtocolError("process event sequence is invalid")
        if type(parsed["limit"]) is not int or not 1 <= parsed["limit"] <= 500:
            raise PipeProtocolError("process event limit must be between 1 and 500")
    elif operation == "get_process_details":
        parsed = _require_payload(payload, {"instance_id"})
        instance_id = parsed["instance_id"]
        if (
            not isinstance(instance_id, str)
            or len(instance_id.encode("utf-8")) > 96
            or not _PROCESS_INSTANCE_ID.fullmatch(instance_id)
        ):
            raise PipeProtocolError("process instance ID is invalid")
    elif operation == "set_process_monitor_profile":
        parsed = _require_payload(payload, {"profile"})
        if parsed["profile"] not in ("low", "normal", "high"):
            raise PipeProtocolError("process sampling profile is invalid")
    elif operation == "start_scan":
        parsed = _require_payload(payload, {"scope"})
        if parsed["scope"] not in ("quick", "system"):
            raise PipeProtocolError("scan scope must be quick or system")
    elif operation == "set_scan_schedule":
        parsed = _require_payload(payload, {"enabled", "frequency", "scope", "local_time", "weekday"})
        if type(parsed["enabled"]) is not bool:
            raise PipeProtocolError("schedule enabled must be a boolean")
        if parsed["frequency"] not in ("daily", "weekly"):
            raise PipeProtocolError("schedule frequency must be daily or weekly")
        if parsed["scope"] not in ("quick", "system"):
            raise PipeProtocolError("schedule scope must be quick or system")
        if not isinstance(parsed["local_time"], str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", parsed["local_time"]):
            raise PipeProtocolError("schedule local_time must use HH:MM")
        weekday = parsed["weekday"]
        if parsed["frequency"] == "weekly":
            if type(weekday) is not int or not 0 <= weekday <= 6:
                raise PipeProtocolError("weekly schedule weekday must be between 0 and 6")
        elif weekday is not None:
            raise PipeProtocolError("daily schedules do not accept a weekday")
    elif operation == "send_agent_message":
        parsed = _require_payload(payload, {"session_id", "message", "detection_id"})
        _require_identifier(parsed["session_id"], "session_id")
        message = parsed["message"]
        if not isinstance(message, str) or not message.strip() or len(message.encode("utf-8")) > 2000:
            raise PipeProtocolError("message must contain between 1 and 2000 bytes")
        detection_id = parsed["detection_id"]
        if detection_id is not None:
            _require_identifier(detection_id, "detection_id")
    elif operation == "claim_sensor_ai_escalations":
        parsed = _require_payload(payload, {"worker_id"})
        _require_identifier(parsed["worker_id"], "worker_id")
    elif operation == "complete_sensor_ai_escalation":
        parsed = _require_payload(payload, {"event_id", "worker_id", "result"})
        _require_identifier(parsed["event_id"], "event_id")
        _require_identifier(parsed["worker_id"], "worker_id")
        result = parsed["result"]
        allowed_result_fields = {
            "analysis", "error", "classification", "confidence",
            "recommended_action", "protection_action",
        }
        if not isinstance(result, dict) or set(result) - allowed_result_fields:
            raise PipeProtocolError("AI result fields do not match the operation schema")
        for key in ("analysis", "error", "classification", "recommended_action", "protection_action"):
            value = result.get(key)
            if value is not None and (not isinstance(value, str) or len(value.encode("utf-8")) > 4000):
                raise PipeProtocolError("AI result text exceeds the size limit")
        confidence = result.get("confidence")
        if confidence is not None and (
            isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1
        ):
            raise PipeProtocolError("AI confidence must be between zero and one")
    return request_id, operation, payload


def process_pipe_request(raw: bytes, host: Any) -> bytes:
    """Validate and dispatch one length-delimited request body."""
    request_id = ""
    try:
        request = _decode_pipe_request(raw)
        candidate_id = request.get("request_id") if isinstance(request, dict) else None
        if isinstance(candidate_id, str) and _REQUEST_ID.fullmatch(candidate_id):
            request_id = candidate_id
        request_id, operation, payload = _validate_pipe_request(request)
        data = host.dispatch(operation, payload)
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
                if not self._authenticated_client(handle):
                    continue
                body_size = int.from_bytes(frame_header, "little")
                if body_size <= 0 or body_size > MAX_FRAME_BYTES:
                    response = process_pipe_request(b"", self)
                else:
                    body = self._read_exact(handle, body_size, win32file, frame_deadline)
                    response = self._request_handler(body)
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

    def _authenticated_client(self, handle: Any) -> bool:
        import win32api
        import win32security

        token = None
        try:
            win32security.ImpersonateNamedPipeClient(handle)
            token = win32security.OpenThreadToken(
                win32api.GetCurrentThread(), win32security.TOKEN_QUERY, True
            )
            token_sid = win32security.GetTokenInformation(
                token, win32security.TokenUser
            )[0]
            sid_text = win32security.ConvertSidToStringSid(token_sid)
            return is_allowed_pipe_client(sid_text, self._client_sid)
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
            except Exception:
                pass

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
        sensor_service: Any | None = None,
        response_coordinator: Any | None = None,
        file_monitor: Any | None = None,
        network_monitor: Any | None = None,
        process_monitor: Any | None = None,
    ) -> None:
        self.store = store
        self.service = service
        self.filter_client = filter_client
        self.triage = triage
        self.rules_trusted = rules_trusted
        self.client_sid = client_sid
        self.pipe_server = pipe_server
        self._windows_security_reader = windows_security_reader
        self.sensor_service = sensor_service
        self.response_coordinator = response_coordinator
        self.file_monitor = file_monitor
        self.network_monitor = network_monitor
        self.process_monitor = process_monitor
        from .scheduling import ScanScheduleManager

        self.scan_scheduler = ScanScheduleManager(store, service)
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
        self._sensor_error: str | None = None
        self._network_telemetry_error: str | None = None
        self._process_monitor_error: str | None = None
        self._process_monitor_start_attempted = False
        self._process_monitor_stop_attempted = False

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._service_state = "running"
        self._stop_event.clear()
        # Publish the bounded status/control pipe before optional sensor startup.
        # Slow or unavailable sensors must not make the dashboard look as if the
        # entire protection service is absent.
        if self.pipe_server is not None:
            try:
                self.pipe_server.start()
            except Exception:
                LOGGER.exception("unable to start the protection named pipe")
                self._last_error = "protection named pipe is unavailable"
        elif not self.client_sid:
            self._last_error = "installed dashboard client SID is not configured"

        if self.process_monitor is not None:
            self._process_monitor_start_attempted = True
            self._process_monitor_stop_attempted = False
            try:
                started = self.process_monitor.start()
                self._process_monitor_error = (
                    "process monitor did not start" if started is False else None
                )
            except Exception:
                LOGGER.exception("unable to start Windows process monitor")
                self._process_monitor_error = "process monitor startup failed"

        if self.network_monitor is not None:
            try:
                started = self.network_monitor.start()
                if started is False:
                    self._network_telemetry_error = "WFP network telemetry did not start"
            except Exception as exc:
                LOGGER.exception("unable to start WFP network telemetry")
                self._network_telemetry_error = (
                    f"{type(exc).__name__}: {exc}"[:256]
                )

        if hasattr(self.store, "get_scan_schedule"):
            if hasattr(self.store, "recover_interrupted_scans"):
                try:
                    recovered = self.store.recover_interrupted_scans()
                    if recovered:
                        LOGGER.warning("marked %s scan job(s) interrupted by a prior service stop", recovered)
                except Exception:
                    LOGGER.exception("unable to recover interrupted scan jobs")
            self.scan_scheduler.start()
        self._start_health_refresh()
        if self.sensor_service is not None:
            try:
                started = self.sensor_service.start()
                self._sensor_error = None if started is not False else "sensor runtime did not start"
            except Exception:
                LOGGER.exception("unable to start Windows sensor runtime")
                self._sensor_error = "sensor runtime startup failed"
        if self.file_monitor is not None:
            try:
                started = self.file_monitor.start()
                if started is False:
                    self._sensor_error = self._sensor_error or "drop-folder file monitor did not start"
            except Exception:
                LOGGER.exception("unable to start Windows drop-folder file monitor")
                self._sensor_error = self._sensor_error or "drop-folder file monitor startup failed"
        if not self.rules_trusted or self.service is None:
            # Keep the loader's actionable error (missing file, bad signature,
            # invalid schema, etc.) so the dashboard can identify the real cause.
            self._last_error = self._last_error or "trusted rule package is unavailable"
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
        self.scan_scheduler.stop(timeout=3.0)
        if (
            self.process_monitor is not None
            and self._process_monitor_start_attempted
            and not self._process_monitor_stop_attempted
        ):
            self._process_monitor_stop_attempted = True
            try:
                self.process_monitor.stop()
            except Exception:
                LOGGER.exception("failed to stop Windows process monitor")
                self._process_monitor_error = "process monitor shutdown failed"
        if self.sensor_service is not None:
            try:
                self.sensor_service.stop(timeout=5.0)
            except Exception:
                LOGGER.exception("failed to stop Windows sensor runtime")
                self._sensor_error = "sensor runtime shutdown failed"
        if self.file_monitor is not None:
            try:
                self.file_monitor.stop(timeout=5.0)
            except Exception:
                LOGGER.exception("failed to stop Windows drop-folder file monitor")
                self._sensor_error = self._sensor_error or "drop-folder file monitor shutdown failed"
        if self.network_monitor is not None:
            try:
                self.network_monitor.stop(timeout=5.0)
            except Exception:
                LOGGER.exception("failed to stop WFP network telemetry")
                self._network_telemetry_error = "WFP network telemetry shutdown failed"
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

    def get_rule_metadata(self) -> dict[str, Any]:
        """Read trusted rule identity without store queries or sensor serialization."""
        trusted = bool(self.rules_trusted and self.service is not None)
        rules = self.service.rules if trusted else None
        entries = getattr(rules, "rules", ())
        return {
            "rules_trusted": trusted,
            "rules_version": rules.version if trusted else "unknown",
            "rule_count": sum(rule.count for rule in entries),
            "sha256_rule_count": sum(rule.count for rule in entries if rule.kind == "sha256"),
            "yara_rule_count": sum(rule.count for rule in entries if rule.kind == "yara"),
            "rules_fingerprint": rule_set_fingerprint(rules) if trusted and hasattr(rules, "rules") else None,
        }

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
            rules_trusted=bool(self.rules_trusted and self.service is not None),
            rule_count=(
                sum(rule.count for rule in getattr(getattr(self.service, "rules", None), "rules", ()))
                if self.rules_trusted and self.service is not None
                else 0
            ),
            sha256_rule_count=(
                sum(rule.count for rule in getattr(getattr(self.service, "rules", None), "rules", ()) if rule.kind == "sha256")
                if self.rules_trusted and self.service is not None
                else 0
            ),
            yara_rule_count=(
                sum(rule.count for rule in getattr(getattr(self.service, "rules", None), "rules", ()) if rule.kind == "yara")
                if self.rules_trusted and self.service is not None
                else 0
            ),
            rules_fingerprint=(
                rule_set_fingerprint(self.service.rules)
                if self.rules_trusted and self.service is not None and hasattr(self.service.rules, "rules")
                else None
            ),
            state=(
                "active"
                if self._started and self.service is not None and self.rules_trusted and connected
                else "unavailable"
                if self.service is None or not self.rules_trusted
                else "degraded"
            ),
            threat_intel=(
                self.service.threat_intel_status()
                if self.service is not None and hasattr(self.service, "threat_intel_status")
                else {"state": "unavailable", "integrity_ok": False, "block_eligible_records": 0, "activation": "inactive"}
            ),
        )
        if self.sensor_service is not None:
            try:
                sensor_status = _to_jsonable(self.sensor_service.get_status())
                if isinstance(sensor_status, dict):
                    from cyber_os.sensors.sensor_registry import REGISTRY_VERSION, build_runtime_registry

                    sensor_status["registry_version"] = REGISTRY_VERSION
                    sensor_status["registry"] = build_runtime_registry(
                        str(sensor_status.get("platform") or "unknown"),
                        sensor_status.get("capabilities") or (),
                    )
                    sensor_status["warnings"] = (
                        self.response_coordinator.get_warnings(limit=100)
                        if self.response_coordinator is not None
                        else []
                    )
                    result["sensors"] = sensor_status
                else:
                    result["sensors"] = {"running": False, "capabilities": [], "registry": []}
            except Exception:
                LOGGER.exception("unable to read Windows sensor runtime status")
                result["sensors"] = {"running": False, "capabilities": []}
                self._sensor_error = "sensor runtime status unavailable"
        else:
            result["sensors"] = {"running": False, "capabilities": []}
        if self.file_monitor is not None:
            try:
                result["sensors"]["drop_folder_watch"] = _to_jsonable(self.file_monitor.get_status())
            except Exception:
                result["sensors"]["drop_folder_watch"] = {"state": "error", "errors": {"status": "unavailable"}}
        if self._sensor_error:
            result["sensor_error"] = self._sensor_error
        if self.network_monitor is None:
            result["network_telemetry"] = {"state": "not_configured"}
        else:
            result["network_telemetry"] = self._network_telemetry_status()
        if self._last_error:
            result["last_error"] = self._last_error
        result["process_monitor"] = self._process_monitor_status()
        file_monitor_status = result.get("sensors", {}).get("drop_folder_watch", {})
        if not isinstance(file_monitor_status, dict):
            file_monitor_status = {}
        scanner_ready = self._scanner_ready()
        file_monitor_running = file_monitor_status.get("state") == "running"
        if connected and self._started and self.rules_trusted and scanner_ready:
            protection_mode = "kernel_realtime"
        elif self._started and self.rules_trusted and scanner_ready and file_monitor_running:
            protection_mode = "user_mode_limited"
        elif self._started and self.rules_trusted and scanner_ready:
            protection_mode = "on_demand_only"
        else:
            protection_mode = "unavailable"
        if not scanner_ready and self.service is not None and self.rules_trusted:
            result["state"] = "degraded"
            result["last_error"] = result.get("last_error") or "trusted scanner rules or required runtime are unavailable"
        result["protection_mode"] = protection_mode
        result["scanner_ready"] = scanner_ready
        result["fallback_coverage"] = {
            "state": "running" if protection_mode == "user_mode_limited" else "unavailable",
            "coverage": file_monitor_status.get("coverage", "post_write_selected_user_folders") if file_monitor_running else "none",
            "roots": file_monitor_status.get("roots", []) if file_monitor_running else [],
            "active_roots": file_monitor_status.get("active_roots", 0),
            "errors": file_monitor_status.get("errors", {}),
            "limitations": [
                "Scans selected user folders after file changes.",
                "Cannot prevent a file from executing before it is scanned.",
                "Does not provide system-wide kernel filtering.",
            ],
        }
        return result

    def _scanner_ready(self) -> bool:
        """Require trusted, non-empty rules and any rule-engine runtime in use."""
        if not self._started or self.service is None or not self.rules_trusted:
            return False
        entries = getattr(getattr(self.service, "rules", None), "rules", ())
        if not entries:
            return False
        if any(getattr(rule, "kind", None) == "yara" for rule in entries):
            try:
                import yara  # noqa: F401
            except ImportError:
                return False
        return True

    def _process_monitor_status(self) -> dict[str, Any]:
        if self.process_monitor is None:
            return {"state": "not_configured", "source": "none"}
        if self._process_monitor_error:
            return {
                "state": "error",
                "source": "protection_service",
                "error": self._process_monitor_error,
            }
        try:
            health = self.process_monitor.health()
        except Exception:
            LOGGER.exception("unable to read Windows process monitor health")
            return {
                "state": "error",
                "source": "protection_service",
                "error": "process monitor health unavailable",
            }
        if not isinstance(health, dict):
            return {
                "state": "error",
                "source": "protection_service",
                "error": "process monitor health unavailable",
            }
        return {**health, "source": "protection_service"}

    def _require_process_monitor(self) -> Any:
        if self.process_monitor is None or self._process_monitor_error:
            raise ProtectionServiceUnavailable("process monitor is unavailable")
        health = self._process_monitor_status()
        if health.get("state") != "running":
            raise ProtectionServiceUnavailable("process monitor is not running")
        return self.process_monitor

    def get_process_snapshot_page(
        self, offset: int, limit: int, sequence: int | None
    ) -> dict[str, Any]:
        monitor = self._require_process_monitor()
        snapshot = _to_jsonable(monitor.snapshot())
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("processes"), list):
            raise ProtectionServiceUnavailable("process snapshot is unavailable")
        processes = snapshot["processes"]
        current_sequence = snapshot.get("sequence")
        if not isinstance(current_sequence, int) or isinstance(current_sequence, bool):
            raise ProtectionServiceUnavailable("process snapshot sequence is unavailable")
        total = len(processes)
        if sequence is not None and sequence != current_sequence:
            return {
                "resync_required": True,
                "sequence": current_sequence,
                "observed_at": snapshot.get("observed_at"),
                "processes": [],
                "offset": offset,
                "next_offset": None,
                "total": total,
                "health": self._process_monitor_status(),
            }

        count = min(limit, max(0, total - offset))
        while True:
            page = {
                "resync_required": False,
                "sequence": current_sequence,
                "observed_at": snapshot.get("observed_at"),
                "processes": processes[offset : offset + count],
                "offset": offset,
                "next_offset": offset + count if offset + count < total else None,
                "total": total,
                "health": self._process_monitor_status(),
            }
            encoded_size = len(
                json.dumps(_to_jsonable(page), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            )
            if encoded_size <= MAX_FRAME_BYTES - 4096:
                return page
            if count <= 1:
                raise ProtectionServiceUnavailable("a process record exceeds the pipe frame limit")
            count = max(1, count // 2)

    def get_process_events(self, after_sequence: int, limit: int) -> dict[str, Any]:
        monitor = self._require_process_monitor()
        current_sequence = getattr(monitor, "current_sequence", None)
        if not isinstance(current_sequence, int):
            snapshot = monitor.snapshot()
            current_sequence = snapshot.get("sequence")
        events = _to_jsonable(monitor.drain_events(after_sequence))
        if not isinstance(events, list):
            raise ProtectionServiceUnavailable("process event history is unavailable")
        resync_required = bool(
            events and events[0].get("sequence", after_sequence + 1) > after_sequence + 1
        )
        if not events and current_sequence > after_sequence:
            retained = _to_jsonable(monitor.drain_events(0))
            resync_required = not retained or bool(
                retained[0].get("sequence", after_sequence + 1) > after_sequence + 1
            )
        delivered = events[:limit]
        return {
            "sequence": (
                delivered[-1].get("sequence", current_sequence)
                if delivered and not resync_required
                else current_sequence
            ),
            "resync_required": resync_required,
            "events": [] if resync_required else delivered,
        }

    def get_process_details(self, instance_id: str) -> dict[str, Any]:
        monitor = self._require_process_monitor()
        details = _to_jsonable(monitor.get_process_details(instance_id))
        if not isinstance(details, dict):
            raise LookupError("process instance not found")
        return details

    def get_process_connections(self) -> dict[str, Any]:
        monitor = self._require_process_monitor()
        connections = _to_jsonable(monitor.connections())
        if not isinstance(connections, list):
            raise ProtectionServiceUnavailable("process connections are unavailable")
        total = len(connections)
        count = total
        observed_at = datetime.now(timezone.utc).isoformat()
        while True:
            data = {
                "connections": connections[:count],
                "total": total,
                "truncated": count < total,
                "observed_at": observed_at,
            }
            size = len(
                json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            )
            if size <= MAX_FRAME_BYTES - 4096:
                return data
            if count <= 1:
                raise ProtectionServiceUnavailable("a process connection exceeds the pipe frame limit")
            count = max(1, count // 2)

    def set_process_monitor_profile(self, profile: str) -> dict[str, Any]:
        monitor = self._require_process_monitor()
        monitor.set_sampling_profile(profile)
        return self._process_monitor_status()

    def _network_telemetry_status(self) -> dict[str, Any]:
        """Derive WFP telemetry status once, for every surface that reports it.

        get_status() and the get_network_telemetry pipe operation must never be
        able to disagree about whether network telemetry is running, so both
        read this single derivation rather than each rebuilding it.
        """
        if self.network_monitor is None:
            return {"state": "not_configured"}
        try:
            network_status = _to_jsonable(self.network_monitor.get_status())
            if not isinstance(network_status, dict):
                network_status = {"state": "unavailable"}
        except Exception:
            LOGGER.exception("unable to read WFP network telemetry status")
            network_status = {"state": "error", "error": "status unavailable"}
        if self._network_telemetry_error:
            network_status["state"] = (
                "error"
                if "failed" in self._network_telemetry_error.lower()
                or ":" in self._network_telemetry_error
                else "unavailable"
            )
            network_status["startup_error"] = self._network_telemetry_error
        return network_status

    def get_network_telemetry(self) -> dict[str, Any]:
        """Return WFP telemetry status plus a bounded recent-event window.

        Read-only: this reports observed connections and never applies a
        network policy. A monitor that is absent or broken yields an explicit
        state and an empty window, never a fabricated "observing".
        """
        status = self._network_telemetry_status()
        if self.network_monitor is None:
            return {"status": status, "events": []}
        try:
            snapshot = _to_jsonable(self.network_monitor.snapshot())
        except Exception:
            LOGGER.exception("unable to read WFP network telemetry events")
            return {"status": status, "events": []}
        if not isinstance(snapshot, list):
            return {"status": status, "events": []}
        return {"status": status, "events": snapshot[-MAX_NETWORK_TELEMETRY_EVENTS:]}

    def handle_request(self, body: bytes) -> bytes:
        return process_pipe_request(body, self)

    def dispatch(self, operation: str, payload: dict[str, Any]) -> Any:
        if operation == "get_status":
            return self.get_status()
        if operation == "get_rule_metadata":
            return self.get_rule_metadata()
        if operation == "get_active_scan":
            job = self.service.get_active_scan() if self.service is not None else None
            return {"active_scan": _to_jsonable(job)}
        if operation == "get_network_telemetry":
            return self.get_network_telemetry()
        if operation == "get_process_snapshot_page":
            return self.get_process_snapshot_page(
                payload["offset"], payload["limit"], payload["sequence"]
            )
        if operation == "get_process_events":
            return self.get_process_events(payload["after_sequence"], payload["limit"])
        if operation == "get_process_monitor_status":
            return self._process_monitor_status()
        if operation == "get_process_details":
            return self.get_process_details(payload["instance_id"])
        if operation == "get_process_connections":
            return self.get_process_connections()
        if operation == "set_process_monitor_profile":
            return self.set_process_monitor_profile(payload["profile"])
        if operation == "get_scan_schedule":
            return self.scan_scheduler.get_schedule()
        if operation == "set_scan_schedule":
            return self.scan_scheduler.configure(**payload)
        if operation == "list_threats":
            records = self.store.list_threats(limit=500)
            return [
                {
                    **{key: value for key, value in asdict(record).items() if key != "intel_evidence"},
                    "threat_intel_evidence": asdict(record.intel_evidence) if record.intel_evidence is not None else None,
                }
                for record in records
            ]
        if operation == "list_quarantine":
            from .quarantine import list_quarantine_items

            return list_quarantine_items(self.store)
        if operation == "list_sensor_warnings":
            if self.response_coordinator is None:
                return []
            return self.response_coordinator.get_warnings(limit=100)
        if operation == "claim_sensor_ai_escalations":
            if self.response_coordinator is None:
                return []
            return self.response_coordinator.claim_ai_escalations(payload["worker_id"])
        if operation == "complete_sensor_ai_escalation":
            if self.response_coordinator is None:
                raise ProtectionServiceUnavailable("sensor response coordinator is unavailable")
            return self.response_coordinator.complete_ai_escalation(
                payload["event_id"], payload["worker_id"], payload["result"]
            )
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
            return {
                "session_id": session_id,
                "detection_id": self.triage.session_detection(session_id),
                "messages": messages,
            }
        if operation == "send_agent_message":
            if self.triage is None:
                raise ProtectionServiceUnavailable("protection triage is unavailable")
            return self.triage.send_message(
                session_id=payload["session_id"],
                message=payload["message"],
                detection_id=payload["detection_id"],
            )
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


def _read_installed_client_sid() -> str | None:
    if os.name != "nt":
        return None
    if os.environ.get("STAI_LOCAL_DEV_SERVICE") == "1":
        # A user-scoped debug service may serve only the identity that launched
        # it. Production installs continue to use the SID enrolled by the MSI.
        try:
            import win32api
            import win32con
            import win32security

            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
            )
            try:
                sid = win32security.GetTokenInformation(
                    token, win32security.TokenUser
                )[0]
                sid_text = win32security.ConvertSidToStringSid(sid)
                return sid_text if _valid_sid_text(sid_text) else None
            finally:
                win32api.CloseHandle(token)
        except (OSError, ImportError):
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


def _read_current_process_sid() -> str | None:
    """Return the current Windows account SID for an explicitly local dev host."""
    if os.name != "nt":
        return None
    token = None
    try:
        import win32api
        import win32con
        import win32security

        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
        )
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        return win32security.ConvertSidToStringSid(sid)
    except Exception:
        return None
    finally:
        if token is not None:
            try:
                win32api.CloseHandle(token)
            except Exception:
                pass


def _resolve_service_client_sid() -> str | None:
    """Use installer identity in production and a user-scoped ACL in local dev."""
    installed_sid = _read_installed_client_sid()
    if installed_sid is not None:
        return installed_sid
    if os.environ.get("STAI_LOCAL_DEV_SERVICE") == "1":
        return _read_current_process_sid()
    return None


def _read_installed_user_profile_root(client_sid: str | None) -> Path | None:
    """Resolve only the enrolled dashboard user's profile from ProfileList."""
    if os.name != "nt" or not client_sid or not _valid_sid_text(client_sid):
        return None
    try:
        import winreg

        key_path = rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{client_sid}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_READ) as key:
            profile, _kind = winreg.QueryValueEx(key, "ProfileImagePath")
        resolved = Path(os.path.expandvars(str(profile))).expanduser()
        return resolved if resolved.is_dir() else None
    except (OSError, ImportError, TypeError, ValueError):
        return None


def _read_installed_user_known_folders(client_sid: str | None) -> dict[str, str]:
    """Read Downloads/Desktop redirections only from the enrolled user's hive."""
    if os.name != "nt" or not client_sid or not _valid_sid_text(client_sid):
        return {}
    try:
        import winreg

        key_path = rf"{client_sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        with winreg.OpenKey(winreg.HKEY_USERS, key_path, 0, winreg.KEY_READ) as key:
            values: dict[str, str] = {}
            for name, value_name in (
                ("Downloads", "{374DE290-123F-4565-9164-39C4925E467B}"),
                ("Desktop", "Desktop"),
            ):
                try:
                    value, _kind = winreg.QueryValueEx(key, value_name)
                    if isinstance(value, str):
                        values[name] = value
                except OSError:
                    continue
        return values
    except (OSError, ImportError):
        return {}


def _installed_user_quick_scan_roots(client_sid: str | None) -> list[Path]:
    """Resolve local Quick Scan roots for the enrolled dashboard user."""
    profile_root = _read_installed_user_profile_root(client_sid)
    if profile_root is None:
        return []
    from cyber_os.sensors.windows_file_watch import monitored_user_roots

    roots = monitored_user_roots(profile_root, _read_installed_user_known_folders(client_sid))
    startup = profile_root / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    try:
        canonical_startup = startup.resolve()
        if canonical_startup.is_dir() and not str(canonical_startup).startswith("\\\\"):
            roots.append(canonical_startup)
    except OSError:
        pass
    return roots


def _create_default_process_monitor() -> Any | None:
    """Create the user-mode process monitor only for the Windows service host."""
    if os.name != "nt":
        return None
    from ui.process_monitor import ProcessRegistry

    return ProcessRegistry(sample_interval=5.0, reconcile_interval=5.0)


def create_default_host() -> ProtectionServiceHost:
    """Build a host only from installed data and the embedded trusted public key."""
    local_data_root = os.environ.get("STAI_PROTECTION_DATA_DIR")
    data_root = (
        Path(local_data_root)
        if os.environ.get("STAI_LOCAL_DEV_SERVICE") == "1" and local_data_root
        else Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "STAI" / "Protection"
    )
    store = ProtectionStore(data_root / "protection.db")
    threat_intel_store = ThreatIntelStore(data_root / "threat-intel.db")
    rules = None
    last_error = None
    public_key_path = _RESOURCE_ROOT / "resources" / "trusted-rules.pub"
    if os.environ.get("STAI_LOCAL_DEV_SERVICE") == "1":
        local_dev_key = os.environ.get("STAI_LOCAL_DEV_TRUSTED_RULES_PUBLIC_KEY")
        if local_dev_key:
            # Source checkouts may use a different trust anchor from the demo
            # key. Keep this override confined to explicit user-scoped dev mode.
            public_key_path = Path(local_dev_key).expanduser()
    manifest_path = data_root / "rules" / "manifest.json"
    signature_path = data_root / "rules" / "manifest.sig"
    try:
        public_key = public_key_path.read_bytes()
    except OSError:
        last_error = "trusted rules public key is not embedded in the service"
    else:
        if len(public_key) != 32:
            last_error = "embedded trusted rules public key has invalid length"
        elif not manifest_path.is_file() or not signature_path.is_file():
            last_error = "trusted rule manifest and signature are not installed"
        else:
            try:
                rules = RulePackage.load(manifest_path, signature_path, public_key)
            except (OSError, InvalidRulePackage) as exc:
                last_error = f"trusted rule package rejected: {exc}"

    client_sid = _resolve_service_client_sid()
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
                threat_intel_store=threat_intel_store,
                quick_scan_roots=(
                    _installed_user_quick_scan_roots(client_sid)
                    if os.name == "nt"
                    else None
                ),
            ),
            on_detection=triage.request,
        )

    filter_client = None
    if os.name == "nt":
        from .filter_client import create_filter_client

        filter_client = create_filter_client()

    sensor_service = None
    response_coordinator = None
    file_monitor = None
    process_monitor = _create_default_process_monitor()
    if os.name == "nt":
        from cyber_os.sensors.windows_sensor_service import WindowsSensorService
        from cyber_os.sensors.warnings import SensorResponseCoordinator, SensorWarningStore
        from cyber_os.sensors.windows_file_watch import WindowsFileActivityMonitor, monitored_user_roots

        response_coordinator = SensorResponseCoordinator(
            SensorWarningStore(str(data_root / "sensor-warnings.sqlite3")),
            protection_service=service,
        )
        sensor_service = WindowsSensorService(
            callback=response_coordinator.submit_event,
            database_path=str(data_root / "sensor-queue.sqlite3"),
        )
        profile_root = _read_installed_user_profile_root(client_sid)
        roots = (
            monitored_user_roots(profile_root, _read_installed_user_known_folders(client_sid))
            if profile_root is not None
            else []
        )
        file_monitor = WindowsFileActivityMonitor(roots, response_coordinator.submit_event)

    host = ProtectionServiceHost(
        store=store,
        service=service,
        filter_client=filter_client,
        triage=triage,
        rules_trusted=rules is not None,
        client_sid=client_sid,
        sensor_service=sensor_service,
        response_coordinator=response_coordinator,
        file_monitor=file_monitor,
        process_monitor=process_monitor,
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
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
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
    if len(sys.argv) == 1:
        # HandleCommandLine is for install/remove/debug CLI verbs. When the
        # Service Control Manager starts the frozen executable, it supplies
        # no arguments; the process must connect to SCM's dispatcher or the
        # service start request times out.
        import servicemanager

        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(STAIProtectionWindowsService)
        servicemanager.StartServiceCtrlDispatcher()
        return
    win32serviceutil.HandleCommandLine(STAIProtectionWindowsService)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
