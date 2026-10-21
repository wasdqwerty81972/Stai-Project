"""The privileged process scan trusts service rules and verifies live identity."""

from types import SimpleNamespace
from unittest.mock import Mock
import threading
import time

import pytest

from cyber_os.protection.models import ScanVerdict
from cyber_os.protection.windows_service import (
    PipeProtocolError,
    ProtectionServiceHost,
    ProtectionServiceUnavailable,
    _validate_pipe_request,
)
from ui.device_process_identity import process_identity


def make_host(tmp_path, monkeypatch, *, action="allow", trusted=True):
    image = tmp_path / "worker.exe"
    image.write_bytes(b"benign test fixture")
    instance_id = process_identity(42, 1.5)
    details = {"instance_id": instance_id, "pid": 42, "create_time": 1.5, "exe": str(image)}
    monitor = SimpleNamespace(get_process_details=lambda _: details, health=lambda: {"state": "running"})
    scanner = Mock()
    scanner.scan_file_for_filter.return_value = (
        ScanVerdict("detected" if action != "allow" else "clean", action, "rule-1", "v1", "a" * 64, "fixture", "rule_match"),
        "detection-1",
    )
    scanner.quarantine_scanned_detection.return_value = SimpleNamespace(success=True, error=None)
    live = SimpleNamespace(create_time=lambda: 1.5, exe=lambda: str(image))
    monkeypatch.setattr("psutil.Process", lambda _: live)
    host = ProtectionServiceHost(store=Mock(), service=scanner, rules_trusted=trusted, process_monitor=monitor)
    return host, scanner, live, image, instance_id


def test_scan_operation_schema_accepts_only_exact_instance():
    body = {"version": 1, "request_id": "a" * 32, "operation": "scan_process_executable", "payload": {"instance_id": process_identity(42, 1.5)}}
    assert _validate_pipe_request(body)[1] == "scan_process_executable"
    body["payload"]["path"] = "C:/arbitrary.exe"
    with pytest.raises(PipeProtocolError):
        _validate_pipe_request(body)


def test_process_scan_requires_service_trusted_rules(tmp_path, monkeypatch):
    host, scanner, _, _, instance = make_host(tmp_path, monkeypatch, trusted=False)
    with pytest.raises(ProtectionServiceUnavailable, match="trusted"):
        host.scan_process_executable(instance)
    scanner.scan_file_for_filter.assert_not_called()


def test_scan_rejects_pid_reuse_before_scanning(tmp_path, monkeypatch):
    host, scanner, live, _, instance = make_host(tmp_path, monkeypatch)
    live.create_time = lambda: 2.0
    with pytest.raises(LookupError, match="identity changed"):
        host.scan_process_executable(instance)
    scanner.scan_file_for_filter.assert_not_called()


def test_scan_rejects_executable_change_before_quarantine(tmp_path, monkeypatch):
    host, scanner, _, image, instance = make_host(tmp_path, monkeypatch, action="block")
    verdict = scanner.scan_file_for_filter.return_value

    def mutate(_):
        image.write_bytes(b"different executable after scan")
        return verdict

    scanner.scan_file_for_filter.side_effect = mutate
    with pytest.raises(ProtectionServiceUnavailable, match="changed during scanning"):
        host.scan_process_executable(instance)
    scanner.quarantine_scanned_detection.assert_not_called()


def test_scan_rechecks_live_identity_before_quarantine(tmp_path, monkeypatch):
    host, scanner, live, _, instance = make_host(tmp_path, monkeypatch, action="block")
    verdict = scanner.scan_file_for_filter.return_value

    def replace_process(_):
        live.create_time = lambda: 2.0
        return verdict

    scanner.scan_file_for_filter.side_effect = replace_process
    with pytest.raises(LookupError, match="identity changed"):
        host.scan_process_executable(instance)
    scanner.quarantine_scanned_detection.assert_not_called()


@pytest.mark.parametrize("action", ["allow", "alert", "block"])
def test_only_confirmed_block_can_be_quarantined(tmp_path, monkeypatch, action):
    host, scanner, _, image, instance = make_host(tmp_path, monkeypatch, action=action)
    result = host.dispatch("scan_process_executable", {"instance_id": instance})
    deadline = time.monotonic() + 2
    while result.get("status") in {"queued", "scanning"} and time.monotonic() < deadline:
        time.sleep(0.01)
        result = host.dispatch("scan_process_executable", {"instance_id": instance})
    scanner.scan_file_for_filter.assert_called_once_with(image)
    assert result["action"] == action
    if action == "block":
        assert result["quarantine"]["state"] == "quarantined"
        scanner.quarantine_scanned_detection.assert_called_once()
    else:
        assert result["quarantine"] is None
        scanner.quarantine_scanned_detection.assert_not_called()


def test_queued_scan_does_not_block_pipe_dispatch(tmp_path, monkeypatch):
    host, scanner, _, image, instance = make_host(tmp_path, monkeypatch)
    entered = threading.Event()
    release = threading.Event()

    def slow_scan(path):
        entered.set()
        assert release.wait(2)
        return scanner.scan_file_for_filter.return_value

    scanner.scan_file_for_filter.side_effect = slow_scan
    first = host.dispatch("scan_process_executable", {"instance_id": instance})
    assert first["status"] == "queued"
    assert entered.wait(2)
    # The service pipe is single-instance; control-plane requests must still
    # complete while the scanner is busy on its worker thread.
    assert host.dispatch("get_process_details", {"instance_id": instance})["pid"] == 42
    assert host.dispatch("scan_process_executable", {"instance_id": instance})["status"] == "scanning"
    release.set()
    result = host.dispatch("scan_process_executable", {"instance_id": instance})
    deadline = time.monotonic() + 2
    while result.get("status") in {"queued", "scanning"} and time.monotonic() < deadline:
        time.sleep(0.01)
        result = host.dispatch("scan_process_executable", {"instance_id": instance})
    assert result["status"] == "clean"
    scanner.scan_file_for_filter.assert_called_once_with(image)
