from __future__ import annotations

import json
import os
import threading
import time
import uuid

import pytest

from cyber_os.protection.windows_service import (
    ProtectionServiceHost,
    WindowsNamedPipeServer,
    build_pipe_sddl,
    is_allowed_pipe_client,
    process_pipe_request,
)


CLIENT_SID = "S-1-5-21-123456789-123456789-123456789-1001"
OTHER_SID = "S-1-5-21-123456789-123456789-123456789-1002"


class _Store:
    def get_status(self, **kwargs):
        return {
            "state": "degraded",
            "driver_state": kwargs["driver_state"],
            "service_state": kwargs["service_state"],
            "rules_version": kwargs.get("rules_version", "unknown"),
            "last_scan": None,
            "counts": {"detected": 0, "blocked": 0, "quarantined": 0},
            "windows_security": {
                "registered_av_provider": None,
                "defender_mode": None,
                "query_available": False,
            },
            "sensor_coverage": {},
            "last_error": kwargs.get("last_error"),
        }


class _FilterClient:
    def __init__(self, connect_result: bool) -> None:
        self.connect_result = connect_result
        self.closed = False

    def connect(self):
        return self.connect_result

    def close(self):
        self.closed = True

    def run_until_stopped(self, service, stop_event, **kwargs):
        del service, kwargs
        stop_event.wait()


class _PipeServer:
    def __init__(self) -> None:
        self.started = False
        self.closed = False

    def start(self):
        self.started = True

    def close(self):
        self.closed = True


class _Service:
    rules = type("Rules", (), {"version": "signed-test-1"})()

    def get_status(self, **kwargs):
        return _Store().get_status(**kwargs)


def test_service_status_is_unavailable_before_driver_and_rules_are_ready():
    host = ProtectionServiceHost(
        store=_Store(),
        service=None,
        filter_client=_FilterClient(False),
        rules_trusted=False,
        client_sid=CLIENT_SID,
    )

    status = host.get_status()

    assert status["state"] == "unavailable"
    assert status["driver_state"] != "running"
    assert status["rules_version"] == "unknown"


def test_service_startup_does_not_claim_active_on_filter_failure():
    pipe_server = _PipeServer()
    host = ProtectionServiceHost(
        store=_Store(),
        service=_Service(),
        filter_client=_FilterClient(False),
        pipe_server=pipe_server,
        rules_trusted=True,
        client_sid=CLIENT_SID,
    )

    host.start()
    status = host.get_status()
    host.stop()

    assert pipe_server.started
    assert status["state"] == "degraded"
    assert status["driver_state"] != "running"


def test_pipe_acl_rejects_untrusted_client():
    sddl = build_pipe_sddl(CLIENT_SID)

    assert is_allowed_pipe_client(CLIENT_SID, CLIENT_SID)
    assert not is_allowed_pipe_client(OTHER_SID, CLIENT_SID)
    assert CLIENT_SID in sddl
    assert ";;;AU)" not in sddl
    assert ";;;WD)" not in sddl


def test_pipe_dispatch_rejects_client_supplied_scan_roots():
    request = {
        "version": 1,
        "request_id": "a" * 32,
        "operation": "start_scan",
        "payload": {"scope": "quick", "roots": ["C:\\"]},
    }

    response = json.loads(process_pipe_request(json.dumps(request).encode(), object()))

    assert response["ok"] is False
    assert "payload" in response["error"].lower()


def test_profile_refresh_rejects_caller_supplied_identity_or_paths():
    request = {
        "version": 1,
        "request_id": "d" * 32,
        "operation": "refresh_scan_profile",
        "payload": {"sid": CLIENT_SID, "roots": ["C:\\"]},
    }

    response = json.loads(process_pipe_request(json.dumps(request).encode(), object()))

    assert response["ok"] is False
    assert "payload" in response["error"].lower()


def test_pipe_request_passes_authenticated_context_outside_json():
    class ContextHost:
        caller = None

        def dispatch(self, operation, payload, *, caller_context=None):
            self.caller = caller_context
            assert operation == "refresh_scan_profile"
            assert payload == {}
            return {"ready": True}

    request = {
        "version": 1,
        "request_id": "e" * 32,
        "operation": "refresh_scan_profile",
        "payload": {},
    }
    caller = type("Caller", (), {"sid": CLIENT_SID, "token_handle": object()})()
    host = ContextHost()

    response = json.loads(process_pipe_request(json.dumps(request).encode(), host, caller))

    assert response["ok"] is True
    assert host.caller is caller


def test_pipe_dispatch_rejects_non_allowlisted_operation():
    request = {
        "version": 1,
        "request_id": "b" * 32,
        "operation": "run_shell_command",
        "payload": {"command": "whoami"},
    }

    response = json.loads(process_pipe_request(json.dumps(request).encode(), object()))

    assert response["ok"] is False
    assert response["request_id"] == "b" * 32


def test_status_does_not_wait_for_slow_windows_health_probe():
    probe_started = threading.Event()
    release_probe = threading.Event()

    def slow_probe():
        probe_started.set()
        release_probe.wait(timeout=2)
        return {"registered_av_provider": "test", "defender_mode": "enabled", "query_available": True}

    host = ProtectionServiceHost(
        store=_Store(),
        service=_Service(),
        filter_client=_FilterClient(False),
        pipe_server=_PipeServer(),
        rules_trusted=True,
        client_sid=CLIENT_SID,
        windows_security_reader=slow_probe,
    )
    try:
        host.start()
        assert probe_started.wait(timeout=1)

        started = time.monotonic()
        status = host.get_status()
        elapsed = time.monotonic() - started

        assert elapsed < 0.2
        assert status["windows_security"]["query_available"] is False
    finally:
        release_probe.set()
        host.stop()


def test_pipe_can_read_stored_threats_while_protection_is_unavailable():
    class ThreatStore(_Store):
        def list_threats(self, limit):
            assert limit == 500
            return []

    host = ProtectionServiceHost(
        store=ThreatStore(),
        service=None,
        rules_trusted=False,
    )
    request = {
        "version": 1,
        "request_id": "c" * 32,
        "operation": "list_threats",
        "payload": {},
    }

    response = json.loads(process_pipe_request(json.dumps(request).encode(), host))

    assert response["ok"] is True
    assert response["data"] == []


def test_windows_named_pipe_round_trips_one_bounded_frame():
    if os.name != "nt":
        pytest.skip("Windows named pipes are available only on Windows")

    win32api = pytest.importorskip("win32api")
    win32file = pytest.importorskip("win32file")
    win32pipe = pytest.importorskip("win32pipe")
    win32security = pytest.importorskip("win32security")
    token = win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32security.TOKEN_QUERY
    )
    try:
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        client_sid = win32security.ConvertSidToStringSid(sid)
    finally:
        win32api.CloseHandle(token)

    pipe_name = rf"\\.\pipe\STAI.Protection.Test.{uuid.uuid4().hex}"
    server = WindowsNamedPipeServer(client_sid, lambda body, caller: body[::-1], pipe_name=pipe_name)
    handle = None
    try:
        server.start()
        deadline = time.monotonic() + 3
        while not server.healthy and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.healthy

        handle = win32file.CreateFile(
            pipe_name,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None,
        )
        payload = b"bounded pipe probe"
        win32file.WriteFile(handle, len(payload).to_bytes(4, "little") + payload)
        _status, header = win32file.ReadFile(handle, 4)
        response_size = int.from_bytes(header, "little")
        _status, response = win32file.ReadFile(handle, response_size)

        assert response == payload[::-1]
    finally:
        if handle is not None:
            win32file.CloseHandle(handle)
        server.close()


def test_named_pipe_partial_frame_read_has_a_deadline():
    class NoDataError(Exception):
        winerror = 232

    class EmptyPipe:
        @staticmethod
        def ReadFile(handle, size):
            raise NoDataError()

    with pytest.raises(TimeoutError, match="frame deadline"):
        WindowsNamedPipeServer._read_exact(
            object(),
            4,
            EmptyPipe,
            time.monotonic() - 0.01,
        )


def test_named_pipe_flush_respects_response_deadline():
    class BlockingFlush:
        @staticmethod
        def FlushFileBuffers(handle):
            del handle
            threading.Event().wait(0.2)

    started = time.monotonic()
    with pytest.raises(TimeoutError, match="response deadline"):
        WindowsNamedPipeServer._flush_with_deadline(
            object(),
            BlockingFlush,
            started + 0.02,
        )
    assert time.monotonic() - started < 0.15
