from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from fastapi import HTTPException
from cyber_os.protection.models import ScanVerdict
from starlette.requests import Request

from ui.api_server import scan_antivirus_process_executable, _scan_process_executable


@pytest.fixture(autouse=True)
def local_scanner_by_default(monkeypatch):
    monkeypatch.setattr("ui.api_server._use_protection_service_pipe", lambda: False)


def request(host="127.0.0.1"):
    return Request({"type": "http", "client": (host, 12345), "headers": []})


class Registry:
    def __init__(self, path: Path):
        self.path = path

    def get_process_details(self, instance_id):
        if instance_id != "42:0x1":
            return None
        return {"pid": 42, "instance_id": instance_id, "exe": str(self.path)}


class Scanner:
    def __init__(self, verdict, detection_id=None):
        self.verdict = verdict
        self.detection_id = detection_id
        self.calls = []
        self.quarantined = []

    def scan_file_for_filter(self, path):
        self.calls.append(path)
        return self.verdict, self.detection_id

    def quarantine_scanned_detection(self, detection_id, path, verdict):
        self.quarantined.append((detection_id, path, verdict))
        return SimpleNamespace(success=True, error=None)


def test_process_executable_scan_returns_evidence_for_exact_instance(tmp_path):
    executable = tmp_path / "worker.exe"
    executable.write_bytes(b"harmless test content")
    verdict = ScanVerdict("clean", "allow", None, "rules-1", "a" * 64, "No signed rule matched", "clean")
    scanner = Scanner(verdict)

    with patch("ui.api_server._get_process_registry", return_value=Registry(executable)), patch(
        "ui.api_server._get_protection_service", return_value=scanner
    ):
        result = _scan_process_executable("42:0x1")

    assert result["instance_id"] == "42:0x1"
    assert result["pid"] == 42
    assert result["status"] == "clean"
    assert result["sha256"] == "a" * 64
    assert scanner.calls == [executable.resolve()]


def test_confirmed_block_is_sent_through_existing_quarantine_policy(tmp_path):
    executable = tmp_path / "worker.exe"
    executable.write_bytes(b"test malware fixture")
    verdict = ScanVerdict("detected", "block", "RULE-1", "rules-1", "b" * 64, "Signed rule matched", "rule_match")
    scanner = Scanner(verdict, "detection-1")

    with patch("ui.api_server._get_process_registry", return_value=Registry(executable)), patch(
        "ui.api_server._get_protection_service", return_value=scanner
    ):
        result = _scan_process_executable("42:0x1")

    assert result["status"] == "detected"
    assert result["detection_id"] == "detection-1"
    assert result["quarantine"]["state"] == "quarantined"
    assert scanner.quarantined[0][0] == "detection-1"


def test_process_scan_rejects_remote_request():
    import pytest

    with pytest.raises(HTTPException) as raised:
        import asyncio
        asyncio.run(scan_antivirus_process_executable("42:0x1", request("192.0.2.1")))
    assert raised.value.status_code == 403


def test_missing_process_instance_cannot_be_scanned(tmp_path):
    import pytest

    with patch("ui.api_server._get_process_registry", return_value=Registry(tmp_path / "gone.exe")):
        with pytest.raises(HTTPException) as raised:
            _scan_process_executable("42:old")
    assert raised.value.status_code == 404


def test_windows_process_scan_uses_service_authority_without_local_fallback(monkeypatch):
    monkeypatch.setattr("ui.api_server._use_protection_service_pipe", lambda: True)
    with patch("ui.api_server._request_protection_pipe", return_value={"status": "clean"}) as pipe, patch(
        "ui.api_server._get_protection_service", side_effect=AssertionError("local scanner must not run")
    ), patch("ui.api_server._process_monitor_call", side_effect=AssertionError("local metadata must not run")):
        assert _scan_process_executable("42:0x1.0p+0") == {"status": "clean"}
    pipe.assert_called_once_with("scan_process_executable", {"instance_id": "42:0x1.0p+0"})


def test_windows_process_scan_polls_queued_service_job(monkeypatch):
    monkeypatch.setattr("ui.api_server._use_protection_service_pipe", lambda: True)
    responses = iter([
        {"instance_id": "42:0x1.0p+0", "status": "queued"},
        {"instance_id": "42:0x1.0p+0", "status": "scanning"},
        {"instance_id": "42:0x1.0p+0", "status": "clean", "action": "allow"},
    ])
    with patch("ui.api_server._request_protection_pipe", side_effect=lambda *_: next(responses)) as pipe, patch(
        "ui.api_server.time.sleep"
    ):
        assert _scan_process_executable("42:0x1.0p+0")["status"] == "clean"
    assert pipe.call_count == 3


def test_windows_scan_reports_service_failure_instead_of_false_clean(monkeypatch):
    monkeypatch.setattr("ui.api_server._use_protection_service_pipe", lambda: True)
    with patch("ui.api_server._protection_pipe_request", side_effect=OSError("offline")), patch(
        "ui.api_server._get_protection_service", side_effect=AssertionError("local scanner must not run")
    ):
        with pytest.raises(HTTPException) as raised:
            _scan_process_executable("42:0x1.0p+0")
    assert raised.value.status_code == 503
