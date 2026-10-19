"""Live firing proof for the sensors that can run in user mode.

These tests deliberately cause *real* operating-system activity (writing files
into a temporary directory, spawning a short-lived child process) and then
assert that the corresponding sensor emitted a matching event.  Nothing here
uses synthetic buffers or hand-built event payloads: the point is to prove the
sensor path end to end, or to skip with an explicit reason when the platform
cannot support it without a driver or administrator rights.
"""

from __future__ import annotations

import ctypes
import os
import platform
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from cyber_os.sensors.windows_file_watch import WindowsFileActivityMonitor
from cyber_os.sensors.windows_sensor_service import (
    SECURITY,
    WindowsEventLogSource,
)
from cyber_os.telemetry import ProcessCollector


WINDOWS_ONLY = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="ReadDirectoryChangesW and the Windows Event Log are Windows-only",
)


def _is_admin() -> bool:
    if platform.system() != "Windows":
        return os.geteuid() == 0  # pragma: no cover - POSIX convenience
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover - defensive
        return False


def _drain(received: "queue.Queue", *, timeout: float) -> list:
    """Collect every event delivered within ``timeout`` seconds."""
    deadline = time.monotonic() + timeout
    events = []
    while time.monotonic() < deadline:
        try:
            events.append(received.get(timeout=max(0.01, deadline - time.monotonic())))
        except queue.Empty:
            break
    return events


# --------------------------------------------------------------------------
# File activity sensor (sensor IDs 49/50): user mode, no driver, no admin
# --------------------------------------------------------------------------


@WINDOWS_ONLY
def test_file_watcher_fires_on_real_file_creation(tmp_path):
    """Create a real executable file and require a real sensor event."""
    received: "queue.Queue" = queue.Queue()
    monitor = WindowsFileActivityMonitor(
        [tmp_path], received.put, settle_seconds=0.15
    )
    assert monitor.start() is True, "monitor refused to start"
    try:
        # Give ReadDirectoryChangesW time to arm before causing activity.
        time.sleep(0.4)
        target = tmp_path / "payload.exe"
        target.write_bytes(b"MZ live-firing probe")

        events = _drain(received, timeout=5.0)
    finally:
        monitor.stop(timeout=5.0)

    assert events, (
        "file watcher produced no event for a real file creation; "
        f"monitor status={monitor.get_status()}"
    )
    event = events[0]
    assert event.event_type == "file_activity"
    assert event.category == "file"
    assert 49 in event.sensor_ids and 50 in event.sensor_ids
    assert event.source == "Windows directory change notification"
    # The executable suffix must be recognised in the privacy-safe summary.
    assert ".exe" in event.details["summary"]


@WINDOWS_ONLY
def test_file_watcher_fires_on_real_file_modification(tmp_path):
    """A second write to an existing file must produce its own event."""
    target = tmp_path / "notes.txt"
    target.write_text("initial")

    received: "queue.Queue" = queue.Queue()
    monitor = WindowsFileActivityMonitor(
        [tmp_path], received.put, settle_seconds=0.15
    )
    assert monitor.start() is True
    try:
        time.sleep(0.4)
        _drain(received, timeout=0.5)  # discard anything from arming
        target.write_text("modified by the live-firing probe")
        events = _drain(received, timeout=5.0)
    finally:
        monitor.stop(timeout=5.0)

    assert events, (
        "file watcher produced no event for a real modification; "
        f"status={monitor.get_status()}"
    )
    assert events[0].details["file_operation"] == "create_or_modify"


@WINDOWS_ONLY
def test_file_watcher_does_not_emit_for_deletion(tmp_path):
    """Document real coverage: deletion is observed but never emitted.

    ``_SCAN_ACTIONS`` excludes ``FILE_ACTION_REMOVED``, so the "File Deletion"
    capability is NOT served by this watcher even though the OS reports it.
    """
    target = tmp_path / "doomed.txt"
    target.write_text("delete me")

    received: "queue.Queue" = queue.Queue()
    monitor = WindowsFileActivityMonitor(
        [tmp_path], received.put, settle_seconds=0.15
    )
    assert monitor.start() is True
    try:
        time.sleep(0.4)
        _drain(received, timeout=0.5)
        target.unlink()
        events = _drain(received, timeout=2.0)
    finally:
        monitor.stop(timeout=5.0)

    assert events == [], (
        "deletion unexpectedly emitted an event; update the sensor coverage "
        "documentation if deletion support was added"
    )


@WINDOWS_ONLY
def test_file_watcher_reports_running_state_while_armed(tmp_path):
    received: "queue.Queue" = queue.Queue()
    monitor = WindowsFileActivityMonitor([tmp_path], received.put)
    assert monitor.start() is True
    try:
        time.sleep(0.3)
        status = monitor.get_status()
        assert status["state"] == "running"
        assert status["active_roots"] == 1
        assert status["errors"] == {}
    finally:
        monitor.stop(timeout=5.0)
    assert monitor.get_status()["state"] != "running"


# --------------------------------------------------------------------------
# Process telemetry: user mode via psutil
# --------------------------------------------------------------------------


def test_process_collector_fires_on_a_real_spawned_process():
    """Spawn a short-lived child and require a matching process event."""
    events: "queue.Queue" = queue.Queue()
    collector = ProcessCollector(events, {"process_poll_interval": 0.5})

    # Establish the baseline synchronously. The first sweep must enrich every
    # running process (~10s on a busy desktop); only steady-state latency is
    # interesting, so do not race it.
    baseline_started = time.monotonic()
    collector.poll_once()
    baseline_seconds = time.monotonic() - baseline_started
    while not events.empty():
        events.get_nowait()

    collector.start()
    try:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(6)"]
        )
        spawned_at = time.monotonic()
        try:
            deadline = time.monotonic() + 15.0
            match = None
            while time.monotonic() < deadline and match is None:
                try:
                    event = events.get(timeout=0.25)
                except queue.Empty:
                    continue
                if event.pid == child.pid:
                    match = event
            latency = time.monotonic() - spawned_at
        finally:
            child.terminate()
            child.wait(timeout=10)
    finally:
        collector.stop()

    assert match is not None, (
        f"ProcessCollector never reported the spawned PID {child.pid}"
    )
    print(
        f"\n[process] baseline sweep {baseline_seconds:.2f}s; "
        f"detection latency {latency:.2f}s"
    )
    assert match.category == "process"
    assert match.process == Path(sys.executable).name.lower()
    assert match.parent_pid == os.getpid(), (
        f"parent PID not attributed: got {match.parent_pid}, "
        f"expected {os.getpid()}"
    )
    assert match.metadata.get("create_time"), "creation time was not collected"
    assert match.file.get("path"), (
        "executable path was not collected -- 'exe' must be requested from "
        "psutil"
    )
    assert match.command_line, "command line was not collected"


def test_process_collector_steady_state_sweep_is_cheap():
    """A sweep that discovers nothing new must not cost seconds of syscalls.

    Re-enriching every process on every pass previously made one sweep take
    longer than ten seconds, which is why short-lived processes were missed.
    """
    events: "queue.Queue" = queue.Queue()
    collector = ProcessCollector(events, {})
    collector.poll_once()  # baseline: enriches every running process

    # A busy machine keeps spawning processes, so time the first sweep that
    # has no new work to do -- that is the steady-state cost.
    elapsed = None
    for _ in range(12):
        started = time.monotonic()
        discovered = collector.poll_once()
        duration = time.monotonic() - started
        if discovered == 0:
            elapsed = duration
            break
    assert elapsed is not None, "never reached a quiet sweep"
    print(f"\n[process] steady-state (0 new) sweep: {elapsed:.4f}s")
    assert elapsed < 0.5, (
        f"a sweep discovering nothing took {elapsed:.2f}s; process discovery "
        "is re-enriching already-known processes"
    )


def test_process_collector_reports_a_reused_pid_as_a_new_process():
    """A recycled PID must not be silently suppressed.

    Windows reuses PIDs aggressively.  If the collector keys only on PID it
    will treat a brand-new process as already-known and never report it, which
    is a detection gap an attacker can wait for.
    """
    events: "queue.Queue" = queue.Queue()
    collector = ProcessCollector(events, {})

    first = {
        "pid": 4242,
        "name": "first.exe",
        "ppid": 1,
        "cmdline": ["first.exe"],
        "create_time": 1000.0,
        "username": "u",
        "exe": r"C:\first.exe",
    }
    second = dict(first)
    second.update(
        {
            "name": "second.exe",
            "cmdline": ["second.exe"],
            "create_time": 2000.0,
            "exe": r"C:\second.exe",
        }
    )

    assert collector.observe(first) is True, "first sighting must be reported"
    assert collector.observe(first) is False, "duplicate sighting must be suppressed"
    assert collector.observe(second) is True, (
        "a different create_time on the same PID is a different process and "
        "must be reported"
    )

    reported = []
    while True:
        try:
            reported.append(events.get_nowait())
        except queue.Empty:
            break
    assert [event.process for event in reported] == ["first.exe", "second.exe"]


def test_process_collector_tracking_table_is_bounded():
    """The known-process table must not grow without limit."""
    events: "queue.Queue" = queue.Queue()
    collector = ProcessCollector(events, {})
    for index in range(collector.max_tracked_processes * 3):
        collector.observe(
            {
                "pid": index,
                "name": f"p{index}.exe",
                "ppid": 1,
                "cmdline": [],
                "create_time": float(index),
                "username": "u",
                "exe": "",
            }
        )
    assert len(collector.known_processes) <= collector.max_tracked_processes


def test_process_collector_emits_termination_for_a_vanished_process():
    events: "queue.Queue" = queue.Queue()
    collector = ProcessCollector(events, {})
    collector.observe(
        {
            "pid": 777,
            "name": "gone.exe",
            "ppid": 1,
            "cmdline": [],
            "create_time": 1.0,
            "username": "u",
            "exe": "",
        }
    )
    while True:
        try:
            events.get_nowait()
        except queue.Empty:
            break

    collector.reap_terminated({1, 2, 3})
    terminated = events.get_nowait()
    assert terminated.category == "process"
    assert terminated.pid == 777
    assert "terminat" in " ".join(terminated.evidence).casefold()
    assert 777 not in collector.known_processes


def test_telemetry_engine_queue_is_bounded_and_counts_drops():
    from cyber_os.telemetry import TelemetryEngine

    engine = TelemetryEngine({"queue_capacity": 4})
    assert engine.event_queue.maxsize == 4
    collector = ProcessCollector(engine.event_queue, {})
    for index in range(20):
        collector.observe(
            {
                "pid": index,
                "name": f"p{index}.exe",
                "ppid": 1,
                "cmdline": [],
                "create_time": float(index),
                "username": "u",
                "exe": "",
            }
        )
    assert engine.event_queue.qsize() == 4
    assert collector.dropped_events == 16


# --------------------------------------------------------------------------
# Network collector: duplication and attribution
# --------------------------------------------------------------------------


def _conn_kwargs(**overrides):
    base = dict(
        local_ip="10.0.0.5",
        local_port=51515,
        remote_ip="93.184.216.34",
        remote_port=443,
        protocol="tcp",
        status="ESTABLISHED",
        pid=1234,
    )
    base.update(overrides)
    return base


def test_network_collector_does_not_re_emit_a_known_connection():
    """One long-lived socket must not produce one event per sweep."""
    from cyber_os.telemetry import NetworkCollector

    events: "queue.Queue" = queue.Queue()
    collector = NetworkCollector(events, {})
    assert collector.observe_connection(**_conn_kwargs()) is True
    for _ in range(50):
        assert collector.observe_connection(**_conn_kwargs()) is False
    assert events.qsize() == 1, (
        f"expected 1 event for 51 sightings of the same connection, got "
        f"{events.qsize()}"
    )


def test_network_collector_tracking_tables_are_bounded():
    from cyber_os.telemetry import NetworkCollector

    events: "queue.Queue" = queue.Queue(maxsize=100_000)
    collector = NetworkCollector(
        events, {"max_tracked_connections": 100, "max_scan_sources": 10}
    )
    for port in range(500):
        collector.observe_connection(**_conn_kwargs(local_port=port))
    assert len(collector.known_connections) <= 100

    for octet in range(200):
        collector._check_port_scan(f"10.1.1.{octet}", 80)
    assert len(collector.port_scan_tracker) <= 10


def test_outbound_fan_out_is_not_reported_as_a_remote_port_scan():
    """Our host contacting many ports of a CDN is not an inbound scan."""
    from cyber_os.telemetry import NetworkCollector

    events: "queue.Queue" = queue.Queue()
    collector = NetworkCollector(events, {"port_scan_threshold": 5})
    for port in range(20):
        collector.observe_connection(
            **_conn_kwargs(local_port=40000 + port, remote_port=port, inbound=False)
        )
    scans = []
    while True:
        try:
            event = events.get_nowait()
        except queue.Empty:
            break
        if event.event_id.startswith("PORT_SCAN_"):
            scans.append(event)
    assert scans == [], (
        "outbound connections were misattributed as an inbound port scan"
    )


def test_inbound_fan_in_is_reported_as_a_port_scan():
    from cyber_os.telemetry import NetworkCollector

    events: "queue.Queue" = queue.Queue()
    collector = NetworkCollector(events, {"port_scan_threshold": 5})
    for port in range(10):
        collector.observe_connection(
            **_conn_kwargs(
                local_port=port, remote_port=60000 + port, inbound=True
            )
        )
    scans = []
    while True:
        try:
            event = events.get_nowait()
        except queue.Empty:
            break
        if event.event_id.startswith("PORT_SCAN_"):
            scans.append(event)
    assert scans, "an inbound fan-in across 10 local ports was not reported"
    assert scans[0].network["direction"] == "inbound"


# --------------------------------------------------------------------------
# Auth collector: the brute-force rule must be reachable at all
# --------------------------------------------------------------------------


def test_brute_force_rule_actually_fires():
    """``failed_logons`` was never populated, so this could never trigger."""
    from cyber_os.telemetry import AuthCollector

    events: "queue.Queue" = queue.Queue()
    collector = AuthCollector(events, {"failed_logon_threshold": 3})
    for index in range(3):
        collector.record_failed_logon(f"record-{index}")

    emitted = []
    while True:
        try:
            emitted.append(events.get_nowait())
        except queue.Empty:
            break
    brute = [e for e in emitted if e.event_id.startswith("BRUTE_FORCE_")]
    assert brute, f"brute-force rule never fired; emitted={[e.event_id for e in emitted]}"
    assert brute[0].severity == "HIGH"
    assert "T1110.001" in brute[0].mitre_techniques


def test_brute_force_window_expires_old_attempts():
    from cyber_os.telemetry import AuthCollector

    events: "queue.Queue" = queue.Queue()
    collector = AuthCollector(
        events, {"failed_logon_threshold": 3, "failed_logon_window": 0.3}
    )
    collector.record_failed_logon("a")
    collector.record_failed_logon("b")
    time.sleep(0.45)
    collector.record_failed_logon("c")
    brute = [
        e for e in _drain(events, timeout=0.1)
        if e.event_id.startswith("BRUTE_FORCE_")
    ]
    assert brute == [], "expired attempts still counted toward the threshold"


# --------------------------------------------------------------------------
# File collector bounds
# --------------------------------------------------------------------------


def test_file_collector_tables_are_bounded(tmp_path):
    from cyber_os.telemetry import FileCollector

    for index in range(50):
        (tmp_path / f"f{index}.txt").write_text("x")
    events: "queue.Queue" = queue.Queue(maxsize=10_000)
    collector = FileCollector(
        events,
        {"watch_dirs": [str(tmp_path)], "max_tracked_files": 20},
    )
    collector.poll_once()
    assert len(collector.last_check_times) <= 20
    assert collector.file_modifications.maxlen is not None


def test_file_collector_detects_a_real_modification(tmp_path):
    from cyber_os.telemetry import FileCollector

    target = tmp_path / "doc.txt"
    target.write_text("one")
    events: "queue.Queue" = queue.Queue()
    collector = FileCollector(events, {"watch_dirs": [str(tmp_path)]})
    assert collector.poll_once() == 0, "baseline sweep must not report changes"
    time.sleep(0.05)
    os.utime(target, (time.time() + 5, time.time() + 5))
    assert collector.poll_once() == 1
    event = events.get_nowait()
    assert event.file["path"] == str(target)
    assert event.category == "file"


# --------------------------------------------------------------------------
# Windows Event Log source: honest availability reporting
# --------------------------------------------------------------------------



@WINDOWS_ONLY
def test_security_event_log_availability_is_reported_honestly():
    """Record whether the Security channel is actually readable here.

    This is not a pass/fail on the product: without administrator rights the
    Security channel cannot be opened at all, which means every capability
    that depends on it (process creation 4688, file auditing 4663, logon
    4624/4625, WFP 5156) cannot fire.  The test asserts the service *says so*
    instead of silently reporting success.
    """
    source = WindowsEventLogSource(channels=[SECURITY])
    source.open()
    status = source.channel_status[SECURITY]
    admin = _is_admin()

    print(f"\n[event-log] running as admin: {admin}")
    print(f"[event-log] Security channel status: {status}")

    assert status["state"] in {"available", "permission_denied", "unavailable", "unsupported"}
    if not admin:
        assert status["state"] != "available" or status["error"] == "", (
            "Security channel reported available without admin; verify the "
            "claim rather than trusting it"
        )
    if status["state"] != "available":
        assert status["error"], "an unavailable channel must explain why"
        pytest.skip(
            f"Security event log is not readable here ({status['state']}: "
            f"{status['error']}); 4688/4663/4624/5156 sensors cannot fire"
        )


@WINDOWS_ONLY
def test_security_event_log_requires_admin_to_read_process_creation():
    """Make the admin requirement explicit and machine-checked."""
    if not _is_admin():
        source = WindowsEventLogSource(channels=[SECURITY])
        source.open()
        state = source.channel_status[SECURITY]["state"]
        assert state != "available", (
            "non-admin process claimed Security log access; the sensor's "
            "availability reporting cannot be trusted"
        )
        pytest.skip(
            "Process Creation (sensor 1) needs administrator rights to read "
            "the Security channel AND 'Audit Process Creation' policy enabled"
        )
    pytest.skip("running elevated; see the audit-policy note in the report")
