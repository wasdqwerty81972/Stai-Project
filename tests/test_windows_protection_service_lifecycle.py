from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from types import ModuleType, SimpleNamespace

import pytest

from cyber_os.protection.models import DetectionRule, RuleSet, ThreatIntelEvidence
from cyber_os.protection.store import DetectionRecord, ProtectionStore
from cyber_os.protection import windows_service as windows_service_module
from cyber_os.protection.windows_service import (
    _validate_pipe_request,
    _installed_user_quick_scan_roots,
    ProtectionServiceHost,
    WindowsNamedPipeServer,
    build_pipe_sddl,
    is_allowed_pipe_client,
    process_pipe_request,
)


CLIENT_SID = "S-1-5-21-123456789-123456789-123456789-1001"
OTHER_SID = "S-1-5-21-123456789-123456789-123456789-1002"


def test_local_dev_service_uses_current_user_sid_when_installer_identity_is_absent(monkeypatch):
    monkeypatch.setattr(
        windows_service_module,
        "os",
        SimpleNamespace(environ={"STAI_LOCAL_DEV_SERVICE": "1"}),
    )
    monkeypatch.setattr(windows_service_module, "_read_installed_client_sid", lambda: None)
    monkeypatch.setattr(windows_service_module, "_read_current_process_sid", lambda: CLIENT_SID)

    assert windows_service_module._resolve_service_client_sid() == CLIENT_SID


def test_installed_client_sid_remains_required_outside_local_dev(monkeypatch):
    monkeypatch.setattr(windows_service_module, "os", SimpleNamespace(environ={}))
    monkeypatch.setattr(windows_service_module, "_read_installed_client_sid", lambda: None)
    monkeypatch.setattr(windows_service_module, "_read_current_process_sid", lambda: CLIENT_SID)

    assert windows_service_module._resolve_service_client_sid() is None


def test_pipe_threat_list_uses_dashboard_intel_evidence_contract(tmp_path):
    store = ProtectionStore(tmp_path / "protection.db")
    evidence = ThreatIntelEvidence(
        indicator_type="sha256", indicator_value="a" * 64,
        source="test-source", verification="reported", confidence=40,
        severity="medium", feed_version="feed-1", first_seen="2026-10-14T10:00:00",
        last_seen="2026-10-14T11:00:00", freshness="fresh", corroborations=1,
    )
    store.record_detection(DetectionRecord(
        detection_id="det-1", sha256="a" * 64, rule_id="threat-intel-advisory",
        rule_version="feed-1", action="allow", confidence="low", severity="medium",
        file_type=".exe", size_bytes=1, file_path="C:/sample.exe",
        created_at="2026-10-14T12:00:00", triage_enqueued=False, intel_evidence=evidence,
    ))
    host = ProtectionServiceHost(store=store, service=None)

    result = host.dispatch("list_threats", {})

    assert result[0]["threat_intel_evidence"]["source"] == "test-source"
    assert "intel_evidence" not in result[0]


def test_windows_service_reports_running_before_waiting_for_stop(monkeypatch):
    service_type = windows_service_module.STAIProtectionWindowsService
    if service_type is None:
        pytest.skip("pywin32 service support is unavailable")

    calls = []

    class Host:
        def start(self):
            calls.append("host-start")

        def stop(self):
            calls.append("host-stop")

    host = Host()
    monkeypatch.setattr(windows_service_module, "create_default_host", lambda: host)
    monkeypatch.setattr(
        windows_service_module.win32event,
        "WaitForSingleObject",
        lambda _event, _timeout: calls.append("wait"),
    )

    class ServiceInstance:
        _host = None
        _stop_event = object()

        def ReportServiceStatus(self, status):
            calls.append(("status", status))

    service_type.SvcDoRun(ServiceInstance())

    assert calls[0] == "host-start"
    assert calls[1] == ("status", windows_service_module.win32service.SERVICE_RUNNING)
    assert calls[2] == "wait"


def test_enrolled_user_quick_scan_roots_use_redirected_folders(tmp_path, monkeypatch):
    profile = tmp_path / "enrolled-user"
    downloads = tmp_path / "redirected" / "Downloads"
    desktop = tmp_path / "redirected" / "Desktop"
    local_temp = profile / "AppData" / "Local" / "Temp"
    startup = profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    for folder in (downloads, desktop, local_temp, startup):
        folder.mkdir(parents=True)

    monkeypatch.setattr(
        "cyber_os.protection.windows_service._read_installed_user_profile_root",
        lambda sid: profile if sid == CLIENT_SID else None,
    )
    monkeypatch.setattr(
        "cyber_os.protection.windows_service._read_installed_user_known_folders",
        lambda _sid: {"Downloads": str(downloads), "Desktop": str(desktop)},
    )

    roots = _installed_user_quick_scan_roots(CLIENT_SID)

    assert set(roots) == {downloads.resolve(), desktop.resolve(), local_temp.resolve(), startup.resolve()}


def test_quick_scan_roots_are_empty_when_enrolled_user_profile_is_unavailable(monkeypatch):
    monkeypatch.setattr("cyber_os.protection.windows_service._read_installed_user_profile_root", lambda _sid: None)

    assert _installed_user_quick_scan_roots(CLIENT_SID) == []


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


class _SensorService:
    def __init__(self, *, starts=True):
        self.starts = starts
        self.start_calls = 0
        self.stop_calls = 0
        self.status = {"running": False, "queue": {"depth": 0}, "capabilities": []}

    def start(self):
        self.start_calls += 1
        self.status["running"] = self.starts
        return self.starts

    def stop(self, timeout=5.0):
        self.stop_calls += 1
        self.status["running"] = False
        return True

    def get_status(self):
        return dict(self.status)


class _FileMonitor:
    def __init__(self):
        self.start_calls = 0
        self.stop_calls = 0

    def start(self):
        self.start_calls += 1
        return True

    def stop(self, timeout=5.0):
        self.stop_calls += 1
        return True

    def get_status(self):
        return {"state": "running", "roots": ["C:/Users/demo/Downloads"]}


class _ProcessMonitor:
    def __init__(self, startup_error=None):
        self.startup_error = startup_error
        self.start_calls = 0
        self.stop_calls = 0

    def start(self):
        self.start_calls += 1
        if self.startup_error is not None:
            raise self.startup_error
        return True

    def stop(self):
        self.stop_calls += 1
        return True

    def snapshot(self):
        return {"sequence": 0, "observed_at": "now", "processes": [], "health": self.health()}

    def health(self):
        return {"state": "running", "event_source": "running", "source": "test-process-monitor"}


def test_host_starts_and_stops_sensor_service_idempotently():
    sensors = _SensorService()
    host = ProtectionServiceHost(
        store=_Store(),
        service=_Service(),
        filter_client=_FilterClient(False),
        pipe_server=_PipeServer(),
        sensor_service=sensors,
        rules_trusted=True,
        client_sid=CLIENT_SID,
    )

    host.start()
    host.start()
    status = host.get_status()
    host.stop()

    assert sensors.start_calls == 1
    assert sensors.stop_calls == 1
    assert status["sensors"]["running"] is True


def test_host_reports_limited_fallback_when_filter_is_disconnected():
    service = _Service()
    service.rules = RuleSet(
        version="signed-test-1",
        rules=(DetectionRule(
            id="test-sha256", kind="sha256", value="a" * 64,
            action="block", confidence="high",
        ),),
    )
    monitor = _FileMonitor()
    host = ProtectionServiceHost(
        store=_Store(),
        service=service,
        filter_client=_FilterClient(False),
        pipe_server=_PipeServer(),
        file_monitor=monitor,
        rules_trusted=True,
        client_sid=CLIENT_SID,
    )

    host.start()
    status = host.get_status()
    host.stop()

    assert status["state"] == "degraded"
    assert status["driver_state"] == "stopped"
    assert status["protection_mode"] == "user_mode_limited"
    assert status["scanner_ready"] is True
    assert status["fallback_coverage"]["state"] == "running"
    assert "Cannot prevent a file from executing before it is scanned." in status["fallback_coverage"]["limitations"]


def test_host_does_not_report_fallback_ready_without_yara_runtime(monkeypatch):
    service = _Service()
    service.rules = RuleSet(
        version="signed-test-1",
        rules=(DetectionRule(
            id="test-yara", kind="yara", value='rule test { condition: true }',
            action="block", confidence="high",
        ),),
    )
    monitor = _FileMonitor()
    monkeypatch.setitem(sys.modules, "yara", None)
    host = ProtectionServiceHost(
        store=_Store(),
        service=service,
        filter_client=_FilterClient(False),
        pipe_server=_PipeServer(),
        file_monitor=monitor,
        rules_trusted=True,
        client_sid=CLIENT_SID,
    )

    host.start()
    status = host.get_status()
    host.stop()

    assert status["state"] == "degraded"
    assert status["protection_mode"] == "unavailable"
    assert status["scanner_ready"] is False
    assert status["fallback_coverage"]["state"] == "unavailable"


def test_host_recovers_interrupted_scan_before_starting_scheduler(tmp_path):
    from cyber_os.protection.store import ProtectionStore

    store = ProtectionStore(tmp_path / "host-recovery.db")
    store.create_scan_job("job-before-restart", "quick")
    store.update_scan_job("job-before-restart", state="running", files_total=3, files_scanned=1)
    host = ProtectionServiceHost(
        store=store,
        service=None,
        filter_client=None,
        rules_trusted=False,
    )

    host.start()
    try:
        job = store.get_scan_job("job-before-restart")
        assert job is not None
        assert job.state == "failed"
        assert job.error_message == "Scan was interrupted when the protection service stopped."
        assert (job.files_total, job.files_scanned) == (3, 1)
    finally:
        host.stop()


def test_sensor_start_failure_is_reported_without_stopping_protection_host():
    sensors = _SensorService(starts=False)
    host = ProtectionServiceHost(
        store=_Store(),
        service=_Service(),
        filter_client=_FilterClient(False),
        pipe_server=_PipeServer(),
        sensor_service=sensors,
        rules_trusted=True,
        client_sid=CLIENT_SID,
    )

    host.start()
    status = host.get_status()
    host.stop()

    assert status["service_state"] == "running"
    assert status["sensors"]["running"] is False
    assert status["sensor_error"] == "sensor runtime did not start"


def test_host_owns_drop_folder_monitor_lifecycle_and_reports_its_status():
    monitor = _FileMonitor()
    host = ProtectionServiceHost(
        store=_Store(),
        service=_Service(),
        filter_client=_FilterClient(False),
        pipe_server=_PipeServer(),
        rules_trusted=True,
        client_sid=CLIENT_SID,
        file_monitor=monitor,
    )

    host.start()
    host.start()
    status = host.get_status()
    host.stop()

    assert monitor.start_calls == 1
    assert monitor.stop_calls == 1
    assert status["sensors"]["drop_folder_watch"]["state"] == "running"


def test_host_starts_and_stops_process_monitor_idempotently():
    monitor = _ProcessMonitor()
    host = ProtectionServiceHost(
        store=_Store(),
        service=_Service(),
        filter_client=_FilterClient(False),
        pipe_server=_PipeServer(),
        rules_trusted=True,
        client_sid=CLIENT_SID,
        process_monitor=monitor,
    )

    host.start()
    host.start()
    status = host.get_status()
    host.stop()
    host.stop()

    assert monitor.start_calls == 1
    assert monitor.stop_calls == 1
    assert status["process_monitor"]["state"] == "running"
    assert status["process_monitor"]["source"] == "protection_service"


def test_process_monitor_start_failure_is_reported_without_stopping_host():
    pipe = _PipeServer()
    monitor = _ProcessMonitor(startup_error=RuntimeError("subscription denied"))
    host = ProtectionServiceHost(
        store=_Store(),
        service=_Service(),
        filter_client=_FilterClient(False),
        pipe_server=pipe,
        rules_trusted=True,
        client_sid=CLIENT_SID,
        process_monitor=monitor,
    )

    host.start()
    status = host.get_status()
    host.stop()

    assert pipe.started is True
    assert status["service_state"] == "running"
    assert status["process_monitor"]["state"] == "error"
    assert status["process_monitor"]["error"] == "process monitor startup failed"


def test_default_process_monitor_factory_uses_registry_on_windows(monkeypatch):
    import cyber_os.protection.windows_service as windows_service

    created = []
    module = ModuleType("ui.process_monitor")

    class RecordingRegistry:
        def __init__(self, **kwargs):
            created.append(kwargs)

    module.ProcessRegistry = RecordingRegistry
    monkeypatch.setitem(sys.modules, "ui.process_monitor", module)
    monkeypatch.setattr(windows_service, "os", SimpleNamespace(name="nt"))

    monitor = windows_service._create_default_process_monitor()

    assert isinstance(monitor, RecordingRegistry)
    assert created == [{"sample_interval": 5.0, "reconcile_interval": 5.0}]


def test_default_host_wires_service_process_monitor_without_api_server(monkeypatch, tmp_path):
    import builtins

    import cyber_os.protection.windows_service as windows_service

    sentinel = object()
    monkeypatch.setattr(windows_service, "_create_default_process_monitor", lambda: sentinel)
    monkeypatch.setattr(
        windows_service,
        "os",
        SimpleNamespace(name="posix", environ={"STAI_LOCAL_DEV_SERVICE": "1", "STAI_PROTECTION_DATA_DIR": str(tmp_path)}),
    )
    monkeypatch.setattr(windows_service, "_RESOURCE_ROOT", tmp_path)
    monkeypatch.setattr(windows_service, "ProtectionStore", lambda path: _Store())

    from cyber_os.protection import ai_provider, triage

    monkeypatch.setattr(ai_provider, "create_default_provider", lambda: None)
    monkeypatch.setattr(triage, "ProtectionTriage", lambda *args, **kwargs: object())
    original_import = builtins.__import__

    def reject_api_server_import(name, *args, **kwargs):
        if name == "ui.api_server":
            raise AssertionError("the frozen protection service must not import the dashboard API")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_api_server_import)
    host = windows_service.create_default_host()

    assert host.process_monitor is sentinel


def test_default_host_reports_missing_trust_anchor_without_installing_demo_rules(monkeypatch, tmp_path):
    import cyber_os.protection.windows_service as windows_service

    data_root = tmp_path / "protection-data"
    resource_root = tmp_path / "service-resources"
    resource_root.mkdir()
    monkeypatch.setattr(
        windows_service,
        "os",
        SimpleNamespace(
            name="posix",
            environ={
                "STAI_LOCAL_DEV_SERVICE": "1",
                "STAI_PROTECTION_DATA_DIR": str(data_root),
            },
        ),
    )
    monkeypatch.setattr(windows_service, "_RESOURCE_ROOT", resource_root)
    monkeypatch.setattr(windows_service, "ProtectionStore", lambda _path: _Store())
    monkeypatch.setattr(windows_service, "_read_installed_client_sid", lambda: None)

    from cyber_os.protection import ai_provider, triage

    monkeypatch.setattr(ai_provider, "create_default_provider", lambda: None)
    monkeypatch.setattr(triage, "ProtectionTriage", lambda *args, **kwargs: object())

    host = windows_service.create_default_host()

    assert host.service is None
    assert host.rules_trusted is False
    assert "public key" in host._last_error.lower()
    assert not (data_root / "rules" / "manifest.json").exists()
    assert not (data_root / "rules" / "manifest.sig").exists()


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


def test_service_status_reports_trusted_rule_counts_and_fingerprint():
    service = _Service()
    service.rules = RuleSet("signed-test-2", (
        DetectionRule("sample-hash", "sha256", "a" * 64, "block", "high"),
        DetectionRule("sample-yara", "yara", "rule sample { condition: true }", "observe", "low"),
    ))
    host = ProtectionServiceHost(
        store=_Store(),
        service=service,
        filter_client=_FilterClient(False),
        pipe_server=_PipeServer(),
        rules_trusted=True,
        client_sid=CLIENT_SID,
    )

    status = host.get_status()

    assert status["rules_trusted"] is True
    assert status["rule_count"] == 2
    assert status["sha256_rule_count"] == 1
    assert status["yara_rule_count"] == 1
    assert len(status["rules_fingerprint"]) == 64


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


def test_service_startup_preserves_specific_rule_package_error():
    host = ProtectionServiceHost(
        store=_Store(),
        service=None,
        filter_client=_FilterClient(False),
        pipe_server=_PipeServer(),
        rules_trusted=False,
        client_sid=CLIENT_SID,
    )
    host._last_error = "trusted rule package rejected: signature mismatch"

    host.start()
    status = host.get_status()
    host.stop()

    assert status["last_error"] == "trusted rule package rejected: signature mismatch"


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


def test_scan_schedule_pipe_payload_requires_typed_local_time_and_weekday():
    base = {
        "version": 1,
        "request_id": "c" * 32,
        "operation": "set_scan_schedule",
        "payload": {
            "enabled": True,
            "frequency": "weekly",
            "scope": "quick",
            "local_time": "03:15",
            "weekday": 2,
        },
    }

    assert _validate_pipe_request(base)[1] == "set_scan_schedule"
    invalid = {**base, "payload": {**base["payload"], "weekday": True}}
    with pytest.raises(ValueError, match="weekday"):
        _validate_pipe_request(invalid)


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
    server = WindowsNamedPipeServer(client_sid, lambda body: body[::-1], pipe_name=pipe_name)
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
