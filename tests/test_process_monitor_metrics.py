import socket
from types import SimpleNamespace

import psutil

from ui.process_monitor import ProcessRegistry


def test_first_cpu_sample_is_unavailable_then_uses_normalized_time_delta(monkeypatch):
    registry = ProcessRegistry()
    registry.reconcile([{"pid": 42, "name": "worker.exe", "create_time": 100.5}])
    row = {
        "pid": 42,
        "name": "worker.exe",
        "create_time": 100.5,
        "cpu_time_seconds": 10.0,
        "memory_bytes": 30 * 1024 * 1024,
        "thread_count": 4,
        "io_read_bytes": 1200,
        "io_write_bytes": 800,
        "io_semantics": "process I/O counters; not physical disk throughput",
    }
    identity = registry.snapshot()["processes"][0]["instance_id"]
    times = iter([9.9, 10.0, 10.05, 10.9, 11.0, 11.05])
    monkeypatch.setattr("ui.process_monitor.time.monotonic", lambda: next(times))
    monkeypatch.setattr(psutil, "cpu_count", lambda: 2)

    registry.sample_metrics([row])
    first = registry.get_process(identity)
    registry.sample_metrics([{**row, "cpu_time_seconds": 11.0, "memory_bytes": 40 * 1024 * 1024}])
    second = registry.get_process(identity)

    assert first["cpu_percent"] is None
    assert first["memory_bytes"] == 30 * 1024 * 1024
    assert second["cpu_percent"] == 50.0
    assert second["memory_bytes"] == 40 * 1024 * 1024
    assert second["io_semantics"] == "process I/O counters; not physical disk throughput"


def test_stale_metric_sample_does_not_restore_a_process_after_exit():
    registry = ProcessRegistry()
    registry.reconcile([{"pid": 42, "name": "worker.exe", "create_time": 100.5}])
    identity = registry.snapshot()["processes"][0]["instance_id"]
    registry.process_stopped({"pid": 42, "event_time": 101.0})

    registry.sample_metrics([{"pid": 42, "create_time": 100.5, "cpu_time_seconds": 999.0}])

    assert registry.get_process(identity) is None


def test_pid_reuse_never_accepts_metrics_for_the_previous_instance():
    registry = ProcessRegistry()
    registry.reconcile([{"pid": 42, "name": "new.exe", "create_time": 101.5}])
    identity = registry.snapshot()["processes"][0]["instance_id"]

    registry.sample_metrics([{"pid": 42, "name": "old.exe", "create_time": 100.5, "cpu_time_seconds": 10.0}])

    process = registry.get_process(identity)
    assert process["name"] == "new.exe"
    assert process["cpu_percent"] is None


def test_connection_owner_is_unknown_when_the_pid_has_been_reused(monkeypatch):
    registry = ProcessRegistry()
    registry.reconcile([{"pid": 42, "name": "old.exe", "create_time": 100.5}])
    connection = SimpleNamespace(
        pid=42,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=("127.0.0.1", 5000),
        raddr=("127.0.0.1", 6000),
        status="ESTABLISHED",
    )
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [connection])
    monkeypatch.setattr(psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 101.5))

    rows = registry.connections()

    assert rows[0]["ownership_status"] == "pid_reused"
    assert rows[0]["process_name"] == "Unknown owner"
    assert rows[0]["instance_id"] is None


def test_connection_owner_validation_is_cached_per_pid_per_snapshot(monkeypatch):
    registry = ProcessRegistry()
    registry.reconcile([{"pid": 42, "name": "worker.exe", "create_time": 100.5}])
    connection = SimpleNamespace(
        pid=42,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
        laddr=("127.0.0.1", 5000),
        raddr=("127.0.0.1", 6000),
        status="ESTABLISHED",
    )
    factory_calls = []
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [connection, connection])
    monkeypatch.setattr(psutil, "Process", lambda pid: factory_calls.append(pid) or SimpleNamespace(create_time=lambda: 100.5))

    rows = registry.connections()

    assert len(rows) == 2
    assert [row["ownership_status"] for row in rows] == ["verified_snapshot", "verified_snapshot"]
    assert factory_calls == [42]


def test_windows_socket_table_failure_is_reported_without_crashing_collector(monkeypatch):
    registry = ProcessRegistry()
    registry.reconcile([{"pid": 42, "name": "worker.exe", "create_time": 100.5}])
    identity = registry.snapshot()["processes"][0]["instance_id"]

    def unavailable(*, kind):
        raise RuntimeError("GetExtendedTcpTable failed")

    monkeypatch.setattr(psutil, "net_connections", unavailable)

    rows = registry.connections()

    assert rows == []
    assert registry.get_process(identity)["network_connection_count"] is None
    assert "GetExtendedTcpTable failed" in registry.health()["last_error"]


def test_repeated_connection_reads_reuse_one_snapshot(monkeypatch):
    registry = ProcessRegistry()
    reads = []
    monkeypatch.setattr(psutil, "net_connections", lambda kind: reads.append(kind) or [])

    registry.connections()
    registry.connections()

    assert reads == ["inet"]


def test_connection_cache_does_not_attribute_exited_owner(monkeypatch):
    registry = ProcessRegistry()
    registry.reconcile([{"pid": 42, "name": "old.exe", "create_time": 100.5}])
    connection = SimpleNamespace(pid=42, family=socket.AF_INET, type=socket.SOCK_STREAM,
        laddr=("127.0.0.1", 5000), raddr=("127.0.0.1", 6000), status="ESTABLISHED")
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [connection])
    monkeypatch.setattr(psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 100.5))
    assert registry.connections()[0]["ownership_status"] == "verified_snapshot"
    registry.reconcile([{"pid": 42, "name": "new.exe", "create_time": 101.5}])

    result = registry.connections()[0]

    assert result["instance_id"] is None
    assert result["process_name"] == "Unknown owner"
