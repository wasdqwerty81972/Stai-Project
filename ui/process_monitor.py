"""Instance-safe Windows process inventory and bounded change history."""

from __future__ import annotations

import copy
import socket
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

import psutil

from ui.device_process_identity import process_identity, resolve_connection_owner
from ui.windows_process_events import SourceStatus, WindowsProcessEventSource


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _cpu_time_seconds(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value.user + value.system)
    except (AttributeError, TypeError, ValueError):
        return None


def _working_set_bytes(value: Any) -> int | None:
    try:
        result = value.rss
    except (AttributeError, TypeError):
        return None
    return int(result) if isinstance(result, int) and not isinstance(result, bool) else None


class ProcessRegistry:
    """Thread-safe live process registry with event and reconciliation inputs.

    Records with a creation timestamp use the application's shared PID plus
    creation-time identity format. When Windows denies that field, a row is
    still shown with an ephemeral unverified ID and is never evidence-eligible.
    """

    def __init__(
        self,
        *,
        process_provider: Callable[[], Iterable[dict[str, Any]]] | None = None,
        event_source: WindowsProcessEventSource | None = None,
        sample_interval: float = 5.0,
        reconcile_interval: float = 5.0,
        event_history_limit: int = 2048,
        on_process_added: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self._process_provider = process_provider or self._enumerate_processes
        self._event_source = event_source or WindowsProcessEventSource()
        self._on_process_added = on_process_added
        self._sample_interval = max(0.25, float(sample_interval))
        self._reconcile_interval = max(self._sample_interval, float(reconcile_interval))
        self._sampling_profile = (
            "normal" if sample_interval == 5.0 and reconcile_interval == 5.0 else "custom"
        )
        self._event_history: deque[dict[str, Any]] = deque(maxlen=max(1, event_history_limit))
        self._processes: dict[str, dict[str, Any]] = {}
        self._pid_to_identity: dict[int, str] = {}
        self._cpu_samples: dict[str, tuple[float, float]] = {}
        self._sequence = 0
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._started = False
        self._last_reconcile = 0.0
        self._last_sample = 0.0
        self._last_sample_duration = 0.0
        self._source_status = SourceStatus("stopped", None, 0)
        self._last_error: str | None = None

    @staticmethod
    def _enumerate_processes() -> list[dict[str, Any]]:
        processes: list[dict[str, Any]] = []
        # Reconciliation only needs a stable identity and display name. Rich
        # metadata, working set, CPU and I/O counters are read by the sampler
        # or on demand; fetching them for every PID made a 300-process snapshot
        # take several seconds on Windows.
        # Parent PID queries are disproportionately slow on protected Windows
        # processes. Reconciliation needs identity and display name; parent PID
        # is loaded on demand in the selected-process details path or from the
        # process-start event payload.
        attrs = ["pid", "name", "create_time"]
        for process in psutil.process_iter(attrs=attrs, ad_value=None):
            info = process.info
            processes.append({
                "pid": process.pid,
                "name": info.get("name"),
                "parent_pid": None,
                "username": None,
                "exe": None,
                # Membership in the snapshot verifies that it is active; the
                # scheduler state is read only when the user opens details.
                "status": "active",
                "create_time": info.get("create_time"),
                "memory_bytes": None,
                "thread_count": None,
                "cpu_time_seconds": None,
                "io_read_bytes": None,
                "io_write_bytes": None,
                "io_semantics": None,
            })
        return processes

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self._stop.clear()
        try:
            self._source_status = self._event_source.start(
                self.process_started, self.process_stopped
            )
        except Exception as exc:
            self._source_status = SourceStatus("unavailable", str(exc), 0)
        self.reconcile()
        with self._lock:
            self._worker = threading.Thread(
                target=self._run,
                name="svs-process-monitor",
                daemon=True,
            )
            self._worker.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._event_source.stop()
        except Exception as exc:
            with self._lock:
                self._last_error = f"Process event source stop failed: {exc}"
        worker = self._worker
        if worker and worker is not threading.current_thread():
            worker.join(timeout=3)
        with self._lock:
            self._started = False
            self._worker = None

    def _run(self) -> None:
        now = time.monotonic()
        next_sample = now
        next_reconcile = now + self._reconcile_interval
        while not self._stop.is_set():
            now = time.monotonic()
            if now >= next_sample:
                self.sample_metrics()
                # Schedule from completion: a large process table can make one
                # sample slower than its interval. Reusing the pre-sample time
                # makes every following cycle immediately overdue and can keep
                # reconciliation waiting behind another expensive sample.
                next_sample = time.monotonic() + self._sample_interval
            now = time.monotonic()
            if now >= next_reconcile:
                self.reconcile()
                self.connections()
                next_reconcile = time.monotonic() + self._reconcile_interval
            wait_for = min(next_sample, next_reconcile) - time.monotonic()
            self._stop.wait(max(0.01, wait_for))

    def set_sampling_profile(self, profile: str) -> None:
        profiles = {
            "low": (10.0, 10.0),
            "normal": (5.0, 5.0),
            "high": (1.0, 2.0),
        }
        if profile not in profiles:
            raise ValueError("Sampling profile must be low, normal, or high")
        sample_interval, reconcile_interval = profiles[profile]
        with self._lock:
            self._sampling_profile = profile
            self._sample_interval = sample_interval
            self._reconcile_interval = reconcile_interval

    def _normalize(self, row: dict[str, Any]) -> dict[str, Any] | None:
        try:
            pid = int(row.get("pid"))
        except (TypeError, ValueError, OverflowError):
            return None
        if pid < 0:
            return None
        create_time = _number(row.get("create_time"))
        verified_id = process_identity(pid, create_time)
        return {
            **copy.deepcopy(row),
            "pid": pid,
            "name": str(row.get("name") or f"Process {pid}"),
            "create_time": create_time,
            "instance_id": verified_id or f"unverified:{pid}:{uuid.uuid4().hex}",
            "identity_verified": verified_id is not None,
            "cpu_percent": None,
            "memory_bytes": row.get("memory_bytes") if isinstance(row.get("memory_bytes"), int) else None,
            "observed_at": _utc_now(),
        }

    def _publish(self, kind: str, process: dict[str, Any]) -> None:
        self._sequence += 1
        self._event_history.append({
            "type": kind,
            "sequence": self._sequence,
            "timestamp": _utc_now(),
            "instance_id": process["instance_id"],
            "pid": process["pid"],
            "process": copy.deepcopy(process),
        })

    def _add_or_replace(self, row: dict[str, Any]) -> dict[str, Any] | None:
        process = self._normalize(row)
        if process is None:
            return None
        pid = process["pid"]
        instance_id = process["instance_id"]
        current_id = self._pid_to_identity.get(pid)
        if current_id and not process["identity_verified"]:
            current = self._processes.get(current_id)
            if current is not None and not current["identity_verified"]:
                process["instance_id"] = instance_id = current_id
        if current_id and current_id != instance_id:
            previous = self._processes.pop(current_id, None)
            if previous is not None:
                self._publish("process_removed", previous)
            self._cpu_samples.pop(current_id, None)
        existing = self._processes.get(instance_id)
        if existing is None:
            process.setdefault("entropy_score", None)
            process.setdefault("entropy_state", "pending")
            process.setdefault("auto_scan_status", "pending")
            self._processes[instance_id] = process
            self._pid_to_identity[pid] = instance_id
            self._publish("process_added", process)
            if self._on_process_added is not None:
                try:
                    self._on_process_added(copy.deepcopy(process))
                except Exception as exc:
                    self._last_error = f"Process analysis enqueue failed: {exc}"
        else:
            # A temporarily inaccessible creation time must not mint a new
            # row on every snapshot. It remains explicitly unverified.
            if not process["identity_verified"] and not existing["identity_verified"]:
                process["instance_id"] = instance_id = existing["instance_id"]
            merged = {**existing, **process}
            for key, value in existing.items():
                # A lightweight reconciliation intentionally omits rich
                # metadata and sampled counters. Do not erase a valid detail
                # sample unless a fresh detail query explicitly reports it.
                if process.get(key) is None and value is not None:
                    merged[key] = value
            self._processes[instance_id] = merged
            self._pid_to_identity[pid] = instance_id
        return self._processes[instance_id]

    def reconcile(self, rows: Iterable[dict[str, Any]] | None = None) -> None:
        try:
            observed = list(self._process_provider() if rows is None else rows)
        except Exception as exc:
            with self._lock:
                self._last_error = f"Process reconciliation failed: {exc}"
            return
        normalized_by_pid: dict[int, dict[str, Any]] = {}
        for row in observed:
            process = self._normalize(row)
            if process is not None:
                normalized_by_pid[process["pid"]] = row
        with self._lock:
            for pid, row in normalized_by_pid.items():
                self._add_or_replace(row)
            observed_pids = set(normalized_by_pid)
            for instance_id, process in list(self._processes.items()):
                if process["pid"] not in observed_pids:
                    self._processes.pop(instance_id, None)
                    if self._pid_to_identity.get(process["pid"]) == instance_id:
                        self._pid_to_identity.pop(process["pid"], None)
                    self._cpu_samples.pop(instance_id, None)
                    self._publish("process_removed", process)
            self._last_reconcile = time.monotonic()
            self._last_error = None

    def process_started(self, event: dict[str, Any]) -> None:
        if not isinstance(event, dict):
            return
        pid = event.get("pid")
        try:
            info = psutil.Process(int(pid)).as_dict(
                attrs=["pid", "name", "ppid", "username", "exe", "status", "create_time", "memory_info", "num_threads"],
                ad_value=None,
            )
            memory = info.get("memory_info")
            self.upsert_process({
                **info,
                "parent_pid": info.get("ppid", event.get("parent_pid")),
                "name": info.get("name") or event.get("name"),
                "memory_bytes": getattr(memory, "rss", None),
            })
        except (psutil.Error, OSError, TypeError, ValueError):
            # Keep an event-only, explicitly unverified row until reconciliation
            # can obtain a process creation time and accessible metadata.
            self.upsert_process({"pid": pid, "name": event.get("name"), "parent_pid": event.get("parent_pid")})

    def upsert_process(self, row: dict[str, Any]) -> None:
        with self._lock:
            self._add_or_replace(row)

    def process_stopped(self, event: dict[str, Any]) -> None:
        if not isinstance(event, dict):
            return
        try:
            pid = int(event.get("pid"))
        except (TypeError, ValueError, OverflowError):
            return
        event_time = _number(event.get("event_time"))
        with self._lock:
            instance_id = self._pid_to_identity.get(pid)
            process = self._processes.get(instance_id or "")
            if process is None:
                return
            create_time = process.get("create_time")
            # A late stop event for an old PID instance must not remove a
            # process that has already been assigned the recycled PID.
            if event_time is None or create_time is None or create_time > event_time:
                return
            self._processes.pop(process["instance_id"], None)
            self._pid_to_identity.pop(pid, None)
            self._cpu_samples.pop(process["instance_id"], None)
            self._publish("process_removed", process)

    def sample_metrics(self, rows: Iterable[dict[str, Any]] | None = None) -> None:
        sample_started = time.monotonic()
        if rows is None:
            # One process_iter pass batches the Windows queries and avoids
            # opening a separate Process handle plus several syscalls per PID.
            # Expensive optional metadata and I/O counters are intentionally
            # excluded from this high-frequency loop.
            try:
                rows = [
                    {
                        "pid": process.pid,
                        **(process.info or {}),
                        "cpu_time_seconds": _cpu_time_seconds((process.info or {}).get("cpu_times")),
                        "memory_bytes": _working_set_bytes((process.info or {}).get("memory_info")),
                    }
                    for process in psutil.process_iter(
                        attrs=["pid", "create_time", "cpu_times", "memory_info"],
                        ad_value=None,
                    )
                ]
            except Exception as exc:
                with self._lock:
                    self._last_error = f"Process metric sample failed: {exc}"
                return
        now = time.monotonic()
        cpu_count = max(1, psutil.cpu_count() or 1)
        with self._lock:
            for row in rows:
                normalized = self._normalize(row)
                if normalized is None or not normalized["identity_verified"]:
                    continue
                process = self._processes.get(normalized["instance_id"])
                if process is None:
                    continue
                cpu_time = _number(row.get("cpu_time_seconds"))
                previous = self._cpu_samples.get(process["instance_id"])
                cpu_percent = None
                if cpu_time is not None and previous and now > previous[0] and cpu_time >= previous[1]:
                    cpu_percent = min(100.0, max(0.0, (cpu_time - previous[1]) / (now - previous[0]) * 100.0 / cpu_count))
                if cpu_time is not None:
                    self._cpu_samples[process["instance_id"]] = (now, cpu_time)
                process["cpu_percent"] = cpu_percent
                process["memory_bytes"] = row.get("memory_bytes") if isinstance(row.get("memory_bytes"), int) else None
                if "thread_count" in row:
                    process["thread_count"] = row.get("thread_count") if isinstance(row.get("thread_count"), int) else None
                if "io_read_bytes" in row or "io_write_bytes" in row:
                    for key in ("io_read_bytes", "io_write_bytes"):
                        value = row.get(key)
                        process[key] = value if isinstance(value, int) and not isinstance(value, bool) else None
                    process["io_semantics"] = row.get("io_semantics")
                process["observed_at"] = _utc_now()
                self._publish("process_metrics_updated", process)
            self._last_sample = now
            self._last_sample_duration = max(0.0, time.monotonic() - sample_started)

    def _remove_instance(self, instance_id: str) -> None:
        with self._lock:
            process = self._processes.pop(instance_id, None)
            if process is None:
                return
            if self._pid_to_identity.get(process["pid"]) == instance_id:
                self._pid_to_identity.pop(process["pid"], None)
            self._cpu_samples.pop(instance_id, None)
            self._publish("process_removed", process)

    def connections(self) -> list[dict[str, Any]]:
        """Return observed TCP/UDP endpoints; psutil does not provide throughput."""
        with self._lock:
            inventory = {
                process["pid"]: copy.deepcopy(process)
                for process in self._processes.values()
            }
        try:
            observed = psutil.net_connections(kind="inet")
        except (psutil.Error, OSError) as exc:
            with self._lock:
                self._last_error = f"Connection enumeration failed: {exc}"
                for process in self._processes.values():
                    process["network_connection_count"] = None
            return []
        result: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        owners: dict[int | None, dict[str, Any]] = {}
        for connection in observed:
            pid = connection.pid if isinstance(connection.pid, int) else None
            if pid not in owners:
                # A socket table commonly has several rows per process. Check
                # PID creation time once per PID for this snapshot, then reuse
                # that verified answer for its rows.
                owners[pid] = resolve_connection_owner(pid, inventory)
            owner = owners[pid]
            if owner["ownership_status"] == "verified_snapshot":
                identity = owner["process_identity"]
                if identity:
                    counts[identity] = counts.get(identity, 0) + 1
            entry = inventory.get(pid) if pid is not None else None
            family = "IPv6" if connection.family == socket.AF_INET6 else "IPv4" if connection.family == socket.AF_INET else "unknown"
            protocol = "TCP" if connection.type == socket.SOCK_STREAM else "UDP" if connection.type == socket.SOCK_DGRAM else "unknown"
            local = getattr(connection, "laddr", None)
            remote = getattr(connection, "raddr", None)
            result.append({
                "pid": pid,
                "instance_id": owner["process_identity"] if owner["ownership_status"] == "verified_snapshot" else None,
                "process_name": owner["process_name"],
                "ownership_status": owner["ownership_status"],
                "family": family,
                "protocol": protocol,
                "local_address": getattr(local, "ip", None) if local else (local[0] if local else None),
                "local_port": getattr(local, "port", None) if local else (local[1] if local else None),
                "remote_address": getattr(remote, "ip", None) if remote else (remote[0] if remote else None),
                "remote_port": getattr(remote, "port", None) if remote else (remote[1] if remote else None),
                "state": getattr(connection, "status", None) or "unavailable",
                "throughput_bytes_per_second": None,
                "observed_at": _utc_now(),
            })
        with self._lock:
            for identity, process in self._processes.items():
                count = counts.get(identity, 0) if process.get("identity_verified") else None
                if process.get("network_connection_count") != count:
                    process["network_connection_count"] = count
                    self._publish("process_metrics_updated", process)
        return result

    def get_process(self, instance_id: str) -> dict[str, Any] | None:
        with self._lock:
            process = self._processes.get(instance_id)
            return copy.deepcopy(process) if process is not None else None

    def update_process_fields(self, instance_id: str, fields: dict[str, Any]) -> dict[str, Any] | None:
        """Attach asynchronous analysis results to the exact live instance."""
        if not isinstance(fields, dict):
            return None
        with self._lock:
            process = self._processes.get(instance_id)
            if process is None:
                return None
            process.update(copy.deepcopy(fields))
            process["observed_at"] = _utc_now()
            self._processes[instance_id] = process
            self._publish("process_metrics_updated", process)
            return copy.deepcopy(process)

    def get_process_details(self, instance_id: str) -> dict[str, Any] | None:
        """Read richer metadata on demand, verifying the PID still names this instance."""
        process = self.get_process(instance_id)
        if process is None:
            return None
        try:
            live = psutil.Process(process["pid"])
            info = live.as_dict(
                attrs=["pid", "name", "ppid", "username", "exe", "status", "create_time", "num_threads"],
                ad_value=None,
            )
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            self._remove_instance(instance_id)
            return None
        except (psutil.AccessDenied, psutil.Error, OSError):
            return process
        if info.get("create_time") != process.get("create_time"):
            # The PID was reused before the periodic inventory caught up.
            self.reconcile()
            return None
        enriched = {
            **process,
            "parent_pid": info.get("ppid"),
            "username": info.get("username"),
            "exe": info.get("exe"),
            "status": info.get("status") or "unavailable",
            "thread_count": info.get("num_threads"),
        }
        with self._lock:
            current = self._processes.get(instance_id)
            if current is None:
                return None
            self._processes[instance_id] = {**current, **enriched}
            return copy.deepcopy(self._processes[instance_id])

    def health(self) -> dict[str, Any]:
        with self._lock:
            status = self._event_source.status
            self._source_status = status
            now = time.monotonic()
            return {
                "state": "running" if self._started else "stopped",
                "event_source": status.state,
                "event_source_name": status.source,
                "event_source_error": status.error,
                "dropped_events": status.dropped_events,
                "last_reconcile_seconds_ago": (
                    max(0.0, now - self._last_reconcile) if self._last_reconcile else None
                ),
                "last_sample_seconds_ago": (
                    max(0.0, now - self._last_sample) if self._last_sample else None
                ),
                "last_sample_duration_seconds": self._last_sample_duration,
                "sample_interval_seconds": self._sample_interval,
                "reconcile_interval_seconds": self._reconcile_interval,
                "sampling_profile": self._sampling_profile,
                "last_error": self._last_error,
            }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            processes = sorted(
                (copy.deepcopy(item) for item in self._processes.values()),
                key=lambda item: item["pid"],
            )
            sequence = self._sequence
        return {
            "sequence": sequence,
            "observed_at": _utc_now(),
            "processes": processes,
            "health": self.health(),
        }

    def drain_events(self, after_sequence: int) -> list[dict[str, Any]]:
        try:
            after = max(0, int(after_sequence))
        except (TypeError, ValueError, OverflowError):
            after = 0
        with self._lock:
            return copy.deepcopy([event for event in self._event_history if event["sequence"] > after])

    @property
    def current_sequence(self) -> int:
        """Return the latest monotonic sequence without copying a process snapshot."""
        with self._lock:
            return self._sequence
