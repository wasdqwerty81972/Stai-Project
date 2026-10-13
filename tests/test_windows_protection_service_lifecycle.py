from __future__ import annotations

import json
import os
import sys
import threading
import time
import types
import uuid

import pytest

from cyber_os.protection.windows_service import (
    ProtectionServiceHost,
    ProtectionServiceUnavailable,
    PipeProtocolError,
    PROTOCOL_VERSION,
    WindowsNamedPipeServer,
    AuthenticatedPipeClient,
    build_pipe_sddl,
    is_allowed_pipe_client,
    process_pipe_request,
    _validate_pipe_request,
)
from cyber_os.protection.store import ProtectionStore


CLIENT_SID = "S-1-5-21-123456789-123456789-123456789-1001"
OTHER_SID = "S-1-5-21-123456789-123456789-123456789-1002"


def test_authenticated_pipe_token_requests_known_folder_access(monkeypatch):
    requested = []
    security = types.SimpleNamespace(
        TOKEN_QUERY=0x0008,
        TOKEN_IMPERSONATE=0x0004,
        TokenUser=1,
        ImpersonateNamedPipeClient=lambda _handle: None,
        OpenThreadToken=lambda _thread, access, _open_as_self: requested.append(access) or 23,
        GetTokenInformation=lambda _token, _kind: ("sid",),
        ConvertSidToStringSid=lambda _sid: CLIENT_SID,
        RevertToSelf=lambda: None,
    )
    api = types.SimpleNamespace(
        GetCurrentThread=lambda: 7,
        CloseHandle=lambda _handle: None,
    )
    monkeypatch.setitem(sys.modules, "win32security", security)
    monkeypatch.setitem(sys.modules, "win32api", api)
    server = WindowsNamedPipeServer(CLIENT_SID, lambda body: body)

    caller = server._authenticated_client(object())

    assert isinstance(caller, AuthenticatedPipeClient)
    assert requested == [security.TOKEN_QUERY | security.TOKEN_IMPERSONATE]
    caller.close()


def test_authenticated_pipe_identity_failure_returns_no_caller(monkeypatch):
    reverted = []
    security = types.SimpleNamespace(
        ImpersonateNamedPipeClient=lambda _handle: (_ for _ in ()).throw(OSError("bad client")),
        RevertToSelf=lambda: reverted.append(True),
    )
    monkeypatch.setitem(sys.modules, "win32security", security)
    monkeypatch.setitem(sys.modules, "win32api", types.SimpleNamespace())
    server = WindowsNamedPipeServer(CLIENT_SID, lambda body: body)

    caller = server._authenticated_client(object())

    assert caller is None
    assert reverted == [True]


def test_host_stop_gates_new_scan_requests():
    class Pipe:
        def close(self):
            pass

    class Service:
        rules = types.SimpleNamespace(version="test")

        def __init__(self):
            self.started = []

        def start_scan(self, scope, **kwargs):
            self.started.append(scope)
            return scope

    service = Service()
    host = ProtectionServiceHost(
        store=_Store(),
        service=service,
        pipe_server=Pipe(),
        rules_trusted=True,
        client_sid=CLIENT_SID,
    )
    host.stop()

    with pytest.raises(ProtectionServiceUnavailable, match="stopping"):
        host.dispatch("start_scan", {"scope": "system"})
    assert service.started == []


def test_stop_during_recovery_prevents_startup_from_reenabling_scheduler():
    recovery_entered = threading.Event()
    release_recovery = threading.Event()

    class Store(_Store):
        def recover_interrupted_scan_jobs(self):
            recovery_entered.set()
            assert release_recovery.wait(timeout=2)

    class Pipe:
        started = False

        def start(self):
            self.started = True

        def close(self):
            pass

    class Service:
        rules = types.SimpleNamespace(version="test")

        def __init__(self):
            self.resumed = 0
            self.due_calls = 0

        def resume_scheduled_scans(self):
            self.resumed += 1

        def run_due_scheduled_scan(self, _sid):
            self.due_calls += 1

    store = Store()
    pipe = Pipe()
    service = Service()
    host = ProtectionServiceHost(
        store=store,
        service=service,
        pipe_server=pipe,
        rules_trusted=True,
        client_sid=CLIENT_SID,
    )
    starter = threading.Thread(target=host.start)
    starter.start()
    assert recovery_entered.wait(timeout=1)

    host.stop()
    release_recovery.set()
    starter.join(timeout=2)

    assert not starter.is_alive()
    assert pipe.started is False
    assert service.resumed == 0
    assert service.due_calls == 0


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


def test_set_scan_schedule_rejects_executable_and_caller_owned_fields():
    request = {
        "version": 1,
        "request_id": "f" * 32,
        "operation": "set_scan_schedule",
        "payload": {
            "enabled": True,
            "cadence": "daily",
            "local_time": "21:30",
            "days_of_week": [],
            "sid": CLIENT_SID,
            "command": "powershell.exe",
        },
    }

    response = json.loads(process_pipe_request(json.dumps(request).encode(), object()))

    assert response["ok"] is False
    assert "payload" in response["error"].lower()


def test_scan_schedule_response_hides_sid_and_profile_paths(tmp_path):
    store = ProtectionStore(tmp_path / "schedule-response.db")
    store.replace_scan_profile(
        CLIENT_SID,
        (("desktop", r"C:\Users\alice\Desktop"),
         ("downloads", r"C:\Users\alice\Downloads"),
         ("startup", r"C:\Users\alice\Startup")),
        "2026-10-12T09:00:00",
    )
    store.set_scan_schedule(
        CLIENT_SID, enabled=True, cadence="daily", local_time="21:30", days_of_week=()
    )
    host = ProtectionServiceHost(
        store=store,
        service=None,
        rules_trusted=False,
        client_sid=CLIENT_SID,
    )
    caller = type("Caller", (), {"sid": CLIENT_SID, "token_handle": object()})()

    result = host.dispatch("get_scan_schedule", {}, caller_context=caller)
    encoded = json.dumps(result)

    assert result["configured"] is True
    assert "owner_sid" not in result
    assert "C:\\Users\\alice" not in encoded


def test_set_scan_schedule_rejects_non_string_weekday_values():
    request = {
        "version": 1,
        "request_id": "9" * 32,
        "operation": "set_scan_schedule",
        "payload": {
            "enabled": True,
            "cadence": "weekly",
            "local_time": "21:30",
            "days_of_week": [[]],
        },
    }

    response = json.loads(process_pipe_request(json.dumps(request).encode(), object()))

    assert response["ok"] is False
    assert "days_of_week" in response["error"]


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


def test_quick_scan_dispatch_requires_exact_enrolled_user():
    host = ProtectionServiceHost(
        store=_Store(),
        service=_Service(),
        filter_client=_FilterClient(False),
        rules_trusted=True,
        client_sid=CLIENT_SID,
    )
    caller = type("Caller", (), {"sid": OTHER_SID, "token_handle": object()})()

    with pytest.raises(ProtectionServiceUnavailable, match="enrolled dashboard user"):
        host.dispatch("start_scan", {"scope": "quick"}, caller_context=caller)


def test_network_snapshot_requires_enrolled_user_and_uses_injected_collector():
    class NetworkCollector:
        calls = 0

        def snapshot(self):
            self.calls += 1
            return {"state": "active", "connections": [], "new_connections": []}

    collector = NetworkCollector()
    host = ProtectionServiceHost(
        store=_Store(),
        service=None,
        rules_trusted=False,
        client_sid=CLIENT_SID,
        network_telemetry=collector,
    )
    caller = type("Caller", (), {"sid": CLIENT_SID, "token_handle": object()})()

    with pytest.raises(ProtectionServiceUnavailable, match="enrolled dashboard user"):
        host.dispatch("get_network_snapshot", {})
    with pytest.raises(ProtectionServiceUnavailable, match="enrolled dashboard user"):
        host.dispatch(
            "get_network_snapshot",
            {},
            caller_context=type("Caller", (), {"sid": OTHER_SID, "token_handle": object()})(),
        )

    response = host.dispatch("get_network_snapshot", {}, caller_context=caller)

    assert response["state"] == "active"
    assert collector.calls == 1

    request = {
        "version": 1,
        "request_id": "d" * 32,
        "operation": "get_network_snapshot",
        "payload": {},
    }
    pipe_response = json.loads(
        process_pipe_request(json.dumps(request).encode(), host, caller)
    )
    assert pipe_response["ok"] is True
    assert pipe_response["data"]["state"] == "active"
    assert collector.calls == 2


def test_firewall_snapshot_requires_enrollment_and_is_read_only():
    class FirewallManager:
        calls = []

        def snapshot(self):
            self.calls.append(("snapshot",))
            return {"state": "active", "profiles": [], "managed_rules": []}

    manager = FirewallManager()
    host = ProtectionServiceHost(
        store=_Store(), service=None, rules_trusted=False, client_sid=CLIENT_SID,
        firewall_manager=manager,
    )
    caller = type("Caller", (), {"sid": CLIENT_SID, "token_handle": object()})()
    with pytest.raises(ProtectionServiceUnavailable, match="enrolled dashboard user"):
        host.dispatch("get_firewall_snapshot", {})
    assert host.dispatch("get_firewall_snapshot", {}, caller_context=caller)["state"] == "active"
    assert manager.calls == [("snapshot",)]


def test_firewall_mutations_are_not_exposed_over_the_local_pipe():
    for operation, payload in (
        ("block_remote_ip", {"remote_address": "8.8.8.8", "user_approved": True}),
        ("remove_firewall_rule", {"rule_id": "SVS Cyber block IP abcdef0123456789", "user_approved": True}),
    ):
        request = {
            "version": PROTOCOL_VERSION,
            "request_id": "d" * 32,
            "operation": operation,
            "payload": payload,
        }
        with pytest.raises(PipeProtocolError):
            _validate_pipe_request(request)



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
