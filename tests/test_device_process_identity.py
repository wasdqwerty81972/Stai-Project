"""A recycled PID must never borrow an earlier process's socket identity."""

from types import SimpleNamespace

import psutil

from ui.device_process_identity import process_identity, resolve_connection_owner


def test_creation_time_distinguishes_recycled_pid():
    assert process_identity(42, 100.5) != process_identity(42, 101.5)
    assert process_identity(42, None) is None


def test_verified_connection_owner_preserves_creation_time():
    inventory = {42: {"name": "browser.exe", "create_time": 100.5}}
    owner = resolve_connection_owner(42, inventory,
        process_factory=lambda pid: SimpleNamespace(create_time=lambda: 100.5))
    assert owner["process_name"] == "browser.exe"
    assert owner["process_create_time"] == 100.5
    assert owner["process_identity"] == process_identity(42, 100.5)
    assert owner["ownership_status"] == "verified_snapshot"


def test_recycled_pid_does_not_borrow_old_process_name():
    owner = resolve_connection_owner(42, {42: {"name": "old.exe", "create_time": 100.5}},
        process_factory=lambda pid: SimpleNamespace(create_time=lambda: 101.5))
    assert owner["ownership_status"] == "pid_reused"
    assert owner["process_name"] == "Unknown owner"
    assert owner["process_identity"] is None


def test_denied_or_missing_creation_time_keeps_ownership_unverified():
    def denied(pid):
        raise psutil.AccessDenied(pid)
    owner = resolve_connection_owner(42, {42: {"name": "protected.exe", "create_time": 100.5}},
        process_factory=denied)
    assert owner["ownership_status"] == "unavailable"
    assert owner["process_identity"] is None
    unavailable = resolve_connection_owner(42, {42: {"name": "unknown.exe", "create_time": None}})
    assert unavailable["ownership_status"] == "unavailable"
    unmapped = resolve_connection_owner(None, {})
    assert unmapped["ownership_status"] == "unmapped"


def test_snapshot_exposes_identity_for_ipv4_ipv6_tcp_udp(monkeypatch):
    import socket
    from ui.device_activity import DeviceActivityCollector
    process = SimpleNamespace(pid=42, info={"name": "network.exe", "username": "user",
        "exe": None, "status": "running", "memory_info": SimpleNamespace(rss=100), "create_time": 100.5},
        cpu_times=lambda: SimpleNamespace(user=1, system=0))
    sockets = [SimpleNamespace(pid=42, family=family, type=kind,
        laddr=("::1" if family == socket.AF_INET6 else "127.0.0.1", 1000),
        raddr=(), status="LISTEN" if kind == socket.SOCK_STREAM else "NONE")
        for family in (socket.AF_INET, socket.AF_INET6)
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM)]
    monkeypatch.setattr(psutil, "process_iter", lambda **kwargs: iter([process]))
    monkeypatch.setattr(psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 100.5))
    monkeypatch.setattr(psutil, "net_connections", lambda **kwargs: sockets)
    monkeypatch.setattr(psutil, "net_io_counters", lambda: SimpleNamespace(bytes_recv=1, bytes_sent=1))
    monkeypatch.setattr(DeviceActivityCollector, "_load_database", lambda *args: None)
    snapshot = DeviceActivityCollector().snapshot()
    assert snapshot["processes"][0]["create_time"] == 100.5
    assert snapshot["processes"][0]["process_identity"] == process_identity(42, 100.5)
    assert {(row["family"], row["protocol"]) for row in snapshot["connections"]} == {
        ("IPv4", "TCP"), ("IPv4", "UDP"), ("IPv6", "TCP"), ("IPv6", "UDP")}
    assert all(row["ownership_status"] == "verified_snapshot" for row in snapshot["connections"])
    assert all(row["process_identity"] == snapshot["processes"][0]["process_identity"]
        for row in snapshot["connections"])
