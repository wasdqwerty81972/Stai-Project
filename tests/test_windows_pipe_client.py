import json
import sys
from types import SimpleNamespace

from cyber_os.protection import windows_pipe_client


class _PipeError(OSError):
    def __init__(self, code):
        super().__init__(code, "pipe is being recreated")
        self.winerror = code


class _PipeModules:
    GENERIC_READ = 1
    GENERIC_WRITE = 2
    OPEN_EXISTING = 3
    PIPE_READMODE_BYTE = 0

    def __init__(self):
        self.wait_calls = 0
        self.open_calls = 0
        self.response = b""

    def WaitNamedPipe(self, _name, _timeout):
        self.wait_calls += 1
        if self.wait_calls == 1:
            raise _PipeError(2)

    def CreateFile(self, *_args):
        self.open_calls += 1
        if self.open_calls == 1:
            raise _PipeError(2)
        return object()

    def SetNamedPipeHandleState(self, *_args):
        return None

    def WriteFile(self, _handle, frame):
        request_size = int.from_bytes(frame[:4], "little")
        request = json.loads(frame[4 : 4 + request_size])
        body = json.dumps({
            "version": 1,
            "request_id": request["request_id"],
            "ok": True,
            "data": {"state": "degraded"},
        }).encode()
        self.response = len(body).to_bytes(4, "little") + body

    def ReadFile(self, _handle, size):
        chunk, self.response = self.response[:size], self.response[size:]
        return 0, chunk

    def CloseHandle(self, _handle):
        return None


def test_retries_when_pipe_instance_disappears_between_wait_and_open(monkeypatch):
    fake = _PipeModules()
    monkeypatch.setattr(windows_pipe_client.os, "name", "nt")
    monkeypatch.setitem(sys.modules, "win32file", fake)
    monkeypatch.setitem(sys.modules, "win32pipe", fake)
    monkeypatch.setattr(windows_pipe_client.time, "sleep", lambda _seconds: None)

    result = windows_pipe_client.request_protection_service("get_status", {}, timeout=0.5)

    assert result == {"state": "degraded"}
    assert fake.wait_calls == 3
    assert fake.open_calls == 2


def test_process_monitor_client_wrappers_use_exact_operations_and_payloads(monkeypatch):
    calls = []
    responses = {
        "get_process_snapshot_page": {
            "sequence": 3, "processes": [], "next_offset": None, "resync_required": False
        },
        "get_process_events": {"sequence": 3, "events": [], "resync_required": False},
        "get_process_monitor_status": {"state": "running"},
        "get_process_details": {"pid": 9},
        "scan_process_executable": {"pid": 9, "status": "clean"},
        "get_process_connections": {"connections": [], "total": 0, "truncated": False},
        "set_process_monitor_profile": {"state": "running", "sampling_profile": "high"},
    }

    def request(operation, payload, *, timeout=5.0):
        calls.append((operation, payload, timeout))
        return responses[operation]

    monkeypatch.setattr(windows_pipe_client, "request_protection_service", request)
    instance_id = "9:0x1.8000000000000p+3"

    assert windows_pipe_client.get_process_snapshot_page(offset=5, limit=12, sequence=3)["sequence"] == 3
    assert windows_pipe_client.get_process_events(after_sequence=2, limit=20)["sequence"] == 3
    assert windows_pipe_client.get_process_monitor_status()["state"] == "running"
    assert windows_pipe_client.get_process_details(instance_id)["pid"] == 9
    assert windows_pipe_client.scan_process_executable(instance_id)["status"] == "clean"
    assert windows_pipe_client.get_process_connections()["total"] == 0
    assert windows_pipe_client.set_process_monitor_profile("high")["sampling_profile"] == "high"

    assert calls == [
        ("get_process_snapshot_page", {"offset": 5, "limit": 12, "sequence": 3}, 5.0),
        ("get_process_events", {"after_sequence": 2, "limit": 20}, 5.0),
        ("get_process_monitor_status", {}, 5.0),
        ("get_process_details", {"instance_id": instance_id}, 5.0),
        ("scan_process_executable", {"instance_id": instance_id}, 5.0),
        ("get_process_connections", {}, 5.0),
        ("set_process_monitor_profile", {"profile": "high"}, 5.0),
    ]


def test_process_monitor_client_wrapper_rejects_malformed_service_data(monkeypatch):
    monkeypatch.setattr(
        windows_pipe_client,
        "request_protection_service",
        lambda *_args, **_kwargs: {"sequence": 1, "processes": "not-a-list"},
    )

    import pytest

    with pytest.raises(ValueError, match="process snapshot"):
        windows_pipe_client.get_process_snapshot_page()
