from __future__ import annotations

import json

import pytest

from cyber_os.protection.windows_service import (
    MAX_FRAME_BYTES,
    PipeProtocolError,
    ProtectionServiceHost,
    _validate_pipe_request,
    process_pipe_request,
)
from ui.device_process_identity import process_identity


class _Store:
    def get_status(self, **_kwargs):
        return {"state": "degraded"}


class _ProcessMonitor:
    def __init__(self, processes=None, connections=None, events=None, sequence=10):
        self.processes = processes or []
        self.connection_rows = connections or []
        self.events = events or []
        self.sequence = sequence
        self.profile = "normal"

    def snapshot(self):
        return {
            "sequence": self.sequence,
            "observed_at": "2026-10-14T00:00:00Z",
            "processes": self.processes,
            "health": self.health(),
        }

    def health(self):
        return {"state": "running", "event_source": "unavailable", "last_error": None}

    def drain_events(self, after_sequence):
        return [item for item in self.events if item["sequence"] > after_sequence]

    def get_process_details(self, instance_id):
        return next((item for item in self.processes if item["instance_id"] == instance_id), None)

    def connections(self):
        return self.connection_rows

    def set_sampling_profile(self, profile):
        self.profile = profile


def _host(monitor):
    return ProtectionServiceHost(store=_Store(), service=None, process_monitor=monitor)


def _request(operation, payload):
    return {
        "version": 1,
        "request_id": "a" * 32,
        "operation": operation,
        "payload": payload,
    }


@pytest.mark.parametrize(
    ("operation", "payload"),
    [
        ("get_process_snapshot_page", {"offset": 0, "limit": 100, "sequence": None}),
        ("get_process_events", {"after_sequence": 0, "limit": 100}),
        ("get_process_monitor_status", {}),
        ("get_process_details", {"instance_id": process_identity(7, 1.5)}),
        ("get_process_details", {"instance_id": "unverified:7:" + "a" * 32}),
        ("get_process_connections", {}),
        ("set_process_monitor_profile", {"profile": "normal"}),
    ],
)
def test_process_pipe_operations_accept_only_the_declared_schemas(operation, payload):
    assert _validate_pipe_request(_request(operation, payload))[1] == operation


@pytest.mark.parametrize(
    ("operation", "payload"),
    [
        ("get_process_snapshot_page", {"offset": True, "limit": 100, "sequence": None}),
        ("get_process_snapshot_page", {"offset": 0, "limit": 501, "sequence": None}),
        ("get_process_snapshot_page", {"offset": 10_000_001, "limit": 1, "sequence": None}),
        ("get_process_snapshot_page", {"offset": 0, "limit": 1, "sequence": False}),
        ("get_process_events", {"after_sequence": -1, "limit": 100}),
        ("get_process_events", {"after_sequence": 0, "limit": 0}),
        ("get_process_details", {"instance_id": "7"}),
        ("get_process_connections", {"block": True}),
        ("set_process_monitor_profile", {"profile": "turbo"}),
    ],
)
def test_process_pipe_operations_reject_malformed_or_extra_fields(operation, payload):
    with pytest.raises(PipeProtocolError):
        _validate_pipe_request(_request(operation, payload))


def test_snapshot_pages_keep_a_stable_sequence_and_report_next_offset():
    monitor = _ProcessMonitor(
        processes=[{"pid": pid, "instance_id": process_identity(pid, 1.5)} for pid in range(5)],
        sequence=20,
    )
    host = _host(monitor)

    page = host.dispatch("get_process_snapshot_page", {"offset": 2, "limit": 2, "sequence": 20})

    assert [row["pid"] for row in page["processes"]] == [2, 3]
    assert page["sequence"] == 20
    assert page["offset"] == 2
    assert page["next_offset"] == 4
    assert page["total"] == 5


def test_snapshot_page_requires_resync_if_registry_sequence_changed():
    host = _host(_ProcessMonitor(processes=[{"pid": 9}], sequence=21))

    page = host.dispatch("get_process_snapshot_page", {"offset": 0, "limit": 1, "sequence": 20})

    assert page["resync_required"] is True
    assert page["sequence"] == 21
    assert page["processes"] == []


def test_process_events_report_a_history_gap_for_snapshot_resync():
    monitor = _ProcessMonitor(
        events=[{"sequence": 10, "type": "process_added"}, {"sequence": 11, "type": "process_removed"}],
        sequence=11,
    )
    host = _host(monitor)

    result = host.dispatch("get_process_events", {"after_sequence": 2, "limit": 10})

    assert result["resync_required"] is True
    assert result["events"] == []
    assert result["sequence"] == 11


def test_process_detail_and_sampling_profile_use_instance_identity():
    instance_id = process_identity(9, 12.5)
    monitor = _ProcessMonitor(processes=[{"pid": 9, "instance_id": instance_id}])
    host = _host(monitor)

    assert host.dispatch("get_process_details", {"instance_id": instance_id})["pid"] == 9
    health = host.dispatch("set_process_monitor_profile", {"profile": "high"})

    assert monitor.profile == "high"
    assert health["state"] == "running"


def test_process_page_is_frame_bounded_without_losing_silent_records():
    processes = [
        {"pid": pid, "instance_id": process_identity(pid, 1.5), "name": "x" * 5000}
        for pid in range(300)
    ]
    host = _host(_ProcessMonitor(processes=processes, sequence=30))
    body = json.dumps(_request("get_process_snapshot_page", {"offset": 0, "limit": 300, "sequence": None})).encode()

    response = process_pipe_request(body, host)
    decoded = json.loads(response)

    assert len(response) < MAX_FRAME_BYTES
    assert decoded["ok"] is True
    page = decoded["data"]
    assert len(page["processes"]) < 300
    assert page["next_offset"] == len(page["processes"])
    assert page["total"] == 300


def test_connection_response_is_bounded_and_marks_truncation():
    connections = [{"owner": "x" * 9000, "index": index} for index in range(300)]
    host = _host(_ProcessMonitor(connections=connections))
    body = json.dumps(_request("get_process_connections", {})).encode()

    response = process_pipe_request(body, host)
    decoded = json.loads(response)

    assert len(response) < MAX_FRAME_BYTES
    assert decoded["ok"] is True
    data = decoded["data"]
    assert data["total"] == 300
    assert data["truncated"] is True
    assert len(data["connections"]) < 300


def test_connection_response_includes_cached_network_snapshot():
    monitor = _ProcessMonitor(connections=[{"pid": 42}])
    monitor.network_snapshot = lambda: {
        "network": {"bytes_sent": 123},
        "observed_at": "2026-10-20T12:00:00Z",
        "errors": ["limited telemetry"],
        "connections": [{"pid": "must not override the bounded list"}],
    }
    result = _host(monitor).get_process_connections()
    assert result["connections"] == [{"pid": 42}]
    assert result["network"] == {"bytes_sent": 123}
    assert result["observed_at"] == "2026-10-20T12:00:00Z"
    assert result["errors"] == ["limited telemetry"]
    assert result["total"] == 1
