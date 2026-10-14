"""
CyberOS Security Telemetry Engine
Centralized collection of security-relevant events from the OS.
"""

import os
import sys
import json
import time
import queue
import threading
import socket
import re
from collections import OrderedDict, deque
from datetime import datetime
from typing import Dict, List, Any, Mapping, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import win32evtlog
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


class EventSeverity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventCategory(Enum):
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    AUTH = "auth"
    PERSISTENCE = "persistence"
    REGISTRY = "registry"
    SERVICE = "service"
    DNS = "dns"
    SECURITY = "security"


@dataclass
class SecurityEvent:
    timestamp: str
    event_id: str
    category: str
    severity: str
    source: str
    host: str
    user: str
    process: str
    pid: int
    parent_pid: int
    command_line: str
    network: Dict[str, Any]
    file: Dict[str, Any]
    evidence: List[str]
    metadata: Dict[str, Any]
    mitre_techniques: List[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'SecurityEvent':
        return cls(**data)

    def get_entities(self) -> Dict[str, List[str]]:
        entities = {
            "processes": [],
            "files": [],
            "network_ips": [],
            "users": [],
            "pids": [],
        }
        if self.process:
            entities["processes"].append(self.process)
        if self.pid:
            entities["pids"].append(str(self.pid))
        if self.parent_pid:
            entities["pids"].append(str(self.parent_pid))
        if self.file.get("path"):
            entities["files"].append(self.file["path"])
        if self.network.get("remote_ip"):
            entities["network_ips"].append(self.network["remote_ip"])
        if self.user:
            entities["users"].append(self.user)
        return entities


class TelemetryCollector:
    """Base class for telemetry collectors."""

    def __init__(self, event_queue: queue.Queue, config: Dict):
        self.event_queue = event_queue
        self.config = config
        self.running = False
        self.thread = None
        # Count of events a full downstream queue forced us to discard, so a
        # saturated pipeline is visible instead of silent.
        self.dropped_events = 0
        self.last_emit_error = ""

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._collect, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _collect(self):
        raise NotImplementedError

    def _emit(self, event: SecurityEvent):
        """Enqueue without blocking; account for backpressure drops."""
        try:
            self.event_queue.put_nowait(event)
        except queue.Full:
            self.dropped_events += 1
        except Exception as exc:
            self.dropped_events += 1
            self.last_emit_error = f"{type(exc).__name__}: {exc}"


_PROCESS_ATTRS = ['pid', 'name', 'ppid', 'cmdline', 'create_time', 'username', 'exe']


class ProcessCollector(TelemetryCollector):
    """Collects process creation and termination events.

    Identity is ``(pid, create_time)``, never the PID alone: Windows recycles
    PIDs aggressively and a PID-only key silently hides every process that
    lands on a recycled number.  The tracking table is bounded so a
    long-running install cannot grow it without limit.
    """

    DEFAULT_MAX_TRACKED = 8192

    def __init__(self, event_queue: queue.Queue, config: Dict):
        super().__init__(event_queue, config)
        # pid -> info mapping of currently-known processes (bounded, FIFO).
        self.known_processes: "OrderedDict[int, Dict[str, Any]]" = OrderedDict()
        self.max_tracked_processes = max(
            16, int(config.get("max_tracked_processes", self.DEFAULT_MAX_TRACKED))
        )
        self.suspicious_chains = config.get("suspicious_chains", [
            ("winword.exe", "cmd.exe"),
            ("excel.exe", "powershell.exe"),
            ("outlook.exe", "cmd.exe"),
            ("chrome.exe", "powershell.exe"),
            ("firefox.exe", "cmd.exe"),
            ("msedge.exe", "powershell.exe"),
        ])
        self.poll_interval = max(0.25, float(config.get("process_poll_interval", 2.0)))

    @staticmethod
    def _identity(info: Mapping[str, Any]) -> tuple:
        """Return the reuse-safe identity of a process sighting."""
        return (info.get('pid'), info.get('create_time'))

    def observe(self, info: Mapping[str, Any]) -> bool:
        """Record one process sighting; return True when it is newly seen.

        ``info`` is a ``psutil`` ``proc.info`` style mapping.  This is the
        single place process identity is decided, so it can be exercised
        directly by tests without spawning hundreds of real processes.
        """
        pid = info.get('pid')
        if pid is None:
            return False
        previous = self.known_processes.get(pid)
        if previous is not None and self._identity(previous) == self._identity(info):
            return False

        record = dict(info)
        self.known_processes[pid] = record
        self.known_processes.move_to_end(pid)
        while len(self.known_processes) > self.max_tracked_processes:
            self.known_processes.popitem(last=False)

        name = (info.get('name') or "").lower()
        cmdline = info.get('cmdline')
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_id=f"PROCESS_CREATE_{pid}_{info.get('create_time', 0)}",
            category=EventCategory.PROCESS.value,
            severity=EventSeverity.INFO.value,
            source="ProcessCollector",
            host=socket.gethostname(),
            user=info.get('username') or 'unknown',
            process=name,
            pid=pid,
            parent_pid=info.get('ppid') or 0,
            command_line=" ".join(cmdline) if cmdline else "",
            network={},
            file={"path": info.get('exe') or ""},
            evidence=[f"Process created: {name} (PID: {pid})"],
            metadata={"create_time": info.get('create_time', 0)},
        )
        self._emit(event)
        self._check_suspicious_chain(record)
        return True

    def reap_terminated(self, live_pids: "set[int]") -> int:
        """Emit termination events for tracked PIDs that are gone.

        This is what keeps ``known_processes`` bounded in practice and is the
        only source of the termination events this collector's docstring
        promises.
        """
        vanished = [pid for pid in self.known_processes if pid not in live_pids]
        for pid in vanished:
            info = self.known_processes.pop(pid, {}) or {}
            name = (info.get('name') or "").lower()
            self._emit(SecurityEvent(
                timestamp=datetime.now().isoformat(),
                event_id=f"PROCESS_TERMINATE_{pid}_{info.get('create_time', 0)}",
                category=EventCategory.PROCESS.value,
                severity=EventSeverity.INFO.value,
                source="ProcessCollector",
                host=socket.gethostname(),
                user=info.get('username') or "",
                process=name,
                pid=pid,
                parent_pid=info.get('ppid') or 0,
                command_line="",
                network={},
                file={"path": info.get('exe') or ""},
                evidence=[f"Process terminated: {name} (PID: {pid})"],
                metadata={"create_time": info.get('create_time', 0)},
            ))
        return len(vanished)

    def _collect(self):
        while self.running:
            try:
                if not PSUTIL_AVAILABLE:
                    time.sleep(self.poll_interval)
                    continue
                self.poll_once()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def poll_once(self) -> int:
        """Run one discovery sweep; return the number of new processes.

        Discovery is deliberately split in two.  ``psutil.pids()`` is a single
        cheap syscall, while fetching ``exe``/``cmdline``/``username`` opens
        each process and costs tens of milliseconds.  Enriching only the PIDs
        we have not seen keeps a steady-state sweep nearly free, so a
        short-lived process is reported within one poll interval instead of
        after a multi-second full enumeration.
        """
        live_pids = set(psutil.pids())
        new_pids = live_pids - self.known_processes.keys()
        discovered = 0
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                info = proc.as_dict(attrs=_PROCESS_ATTRS, ad_value=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # A process we cannot open is still a process that exists;
                # record the identity we do have so it is not re-probed and
                # so its termination is still reported.
                info = {'pid': pid, 'name': '', 'ppid': 0, 'cmdline': None,
                        'create_time': 0, 'username': None, 'exe': None}
            except Exception:
                continue
            info['pid'] = pid
            if self.observe(info):
                discovered += 1
        self.reap_terminated(live_pids)
        return discovered

    def _check_suspicious_chain(self, info: Mapping[str, Any]) -> None:
        """Match parent/child names using data already collected.

        The previous implementation called ``proc.parent()`` and
        ``parent.name()`` per new process.  Those are ~35 ms of syscalls each
        on Windows, which made a single baseline sweep of ~330 processes take
        longer than ten seconds -- long enough that short-lived processes were
        never observed at all.  ``ppid`` and ``name`` are already present in
        the sighting, so no extra syscall is needed.
        """
        child_name = (info.get('name') or "").lower()
        parent_pid = info.get('ppid') or 0
        if not child_name or not parent_pid:
            return
        parent = self.known_processes.get(parent_pid)
        if not parent:
            return
        parent_name = (parent.get('name') or "").lower()
        if not parent_name:
            return
        for suspicious_parent, suspicious_child in self.suspicious_chains:
            if parent_name == suspicious_parent and child_name == suspicious_child:
                cmdline = info.get('cmdline')
                self._emit(SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_id=f"SUSPICIOUS_CHAIN_{info.get('pid')}_{info.get('create_time', 0)}",
                    category=EventCategory.PROCESS.value,
                    severity=EventSeverity.HIGH.value,
                    source="ProcessCollector",
                    host=socket.gethostname(),
                    user=info.get('username') or "",
                    process=child_name,
                    pid=info.get('pid') or 0,
                    parent_pid=parent_pid,
                    command_line=" ".join(cmdline) if cmdline else "",
                    network={},
                    file={},
                    evidence=[
                        f"Suspicious parent-child: {parent_name} -> {child_name}",
                        f"Parent PID: {parent_pid}",
                        f"Child PID: {info.get('pid')}",
                    ],
                    metadata={"chain": f"{parent_name} -> {child_name}"},
                    mitre_techniques=["T1059.001"],
                ))
                return


class NetworkCollector(TelemetryCollector):
    """Collects network connection events.

    Only *transitions* are reported.  The previous implementation re-emitted
    an event for every established connection on every pass, so a single
    long-lived socket produced one duplicate event per second forever.
    """

    DEFAULT_MAX_TRACKED = 8192
    DEFAULT_MAX_SCAN_SOURCES = 1024

    def __init__(self, event_queue: queue.Queue, config: Dict):
        super().__init__(event_queue, config)
        self.port_scan_tracker: "OrderedDict[str, list]" = OrderedDict()
        self.scan_threshold = config.get("port_scan_threshold", 10)
        self.scan_window = config.get("port_scan_window", 30)
        self.poll_interval = max(0.25, float(config.get("network_poll_interval", 1.0)))
        self.max_tracked_connections = max(
            16, int(config.get("max_tracked_connections", self.DEFAULT_MAX_TRACKED))
        )
        self.max_scan_sources = max(
            4, int(config.get("max_scan_sources", self.DEFAULT_MAX_SCAN_SOURCES))
        )
        # Set of connection keys reported in the previous sweep.
        self.known_connections: "OrderedDict[tuple, float]" = OrderedDict()

    @staticmethod
    def _key(local_ip, local_port, remote_ip, remote_port, protocol, pid) -> tuple:
        return (local_ip, local_port, remote_ip, remote_port, protocol, pid)

    def observe_connection(
        self,
        *,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        protocol: str,
        status: str,
        pid: int = 0,
        inbound: bool = False,
    ) -> bool:
        """Report one connection if it was not already known. True when new."""
        key = self._key(local_ip, local_port, remote_ip, remote_port, protocol, pid)
        if key in self.known_connections:
            self.known_connections.move_to_end(key)
            return False
        self.known_connections[key] = time.time()
        while len(self.known_connections) > self.max_tracked_connections:
            self.known_connections.popitem(last=False)

        self._emit(SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_id=(
                f"NETWORK_CONN_{local_ip}_{local_port}_"
                f"{remote_ip}_{remote_port}_{protocol}"
            ),
            category=EventCategory.NETWORK.value,
            severity=EventSeverity.INFO.value,
            source="NetworkCollector",
            host=socket.gethostname(),
            user="",
            process="",
            pid=pid,
            parent_pid=0,
            command_line="",
            network={
                "local_addr": f"{local_ip}:{local_port}",
                "remote_addr": f"{remote_ip}:{remote_port}",
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "local_port": local_port,
                "protocol": protocol,
                "status": status,
                "direction": "inbound" if inbound else "outbound",
            },
            file={},
            evidence=[f"Connection: {local_ip}:{local_port} -> {remote_ip}:{remote_port}"],
            metadata={"connection_state": status},
        ))
        # Only inbound traffic can evidence a remote host scanning *us*. An
        # outbound connection to many ports of one host is ordinary client
        # behaviour (CDNs, update services) and must not be attributed to the
        # remote address as a scan.
        if inbound:
            self._check_port_scan(remote_ip, local_port)
        return True

    def _prune_connections(self, live_keys: set) -> None:
        """Forget connections that are no longer present."""
        for key in [k for k in self.known_connections if k not in live_keys]:
            self.known_connections.pop(key, None)

    def _collect(self):
        while self.running:
            try:
                if not PSUTIL_AVAILABLE:
                    time.sleep(self.poll_interval)
                    continue
                self.poll_once()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def poll_once(self) -> int:
        """One connection sweep; returns the count of newly seen connections."""
        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, PermissionError) as exc:
            # Without elevation Windows only reveals this process's own
            # sockets. Record it rather than silently reporting nothing.
            self.last_emit_error = f"net_connections denied: {type(exc).__name__}"
            return 0
        live_keys = set()
        new_count = 0
        for conn in connections:
            if not conn.laddr or not conn.raddr:
                continue
            local_ip, local_port = conn.laddr[0], conn.laddr[1]
            remote_ip, remote_port = conn.raddr[0], conn.raddr[1]
            protocol = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
            pid = conn.pid or 0
            live_keys.add(
                self._key(local_ip, local_port, remote_ip, remote_port, protocol, pid)
            )
            inbound = conn.status == getattr(psutil, "CONN_SYN_RECV", "SYN_RECV")
            if self.observe_connection(
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                protocol=protocol,
                status=conn.status,
                pid=pid,
                inbound=inbound,
            ):
                new_count += 1
        self._prune_connections(live_keys)
        return new_count

    def _check_port_scan(self, remote_ip: str, scanned_port: int):
        now = time.time()
        if remote_ip not in self.port_scan_tracker:
            self.port_scan_tracker[remote_ip] = []
        self.port_scan_tracker[remote_ip].append((now, scanned_port))
        self.port_scan_tracker.move_to_end(remote_ip)

        cutoff = now - self.scan_window
        recent = [(t, p) for t, p in self.port_scan_tracker[remote_ip] if t > cutoff]
        self.port_scan_tracker[remote_ip] = recent
        # Drop sources that have gone quiet, then bound the table itself.
        for ip in [k for k, v in self.port_scan_tracker.items() if not v]:
            self.port_scan_tracker.pop(ip, None)
        while len(self.port_scan_tracker) > self.max_scan_sources:
            self.port_scan_tracker.popitem(last=False)

        unique_ports = {p for _, p in recent}
        if len(unique_ports) >= self.scan_threshold:
            self._emit(SecurityEvent(
                timestamp=datetime.now().isoformat(),
                event_id=f"PORT_SCAN_{remote_ip}_{int(now)}",
                category=EventCategory.NETWORK.value,
                severity=EventSeverity.HIGH.value,
                source="NetworkCollector",
                host=socket.gethostname(),
                user="",
                process="",
                pid=0,
                parent_pid=0,
                command_line="",
                network={
                    "remote_ip": remote_ip,
                    "scanned_ports": sorted(unique_ports)[:20],
                    "direction": "inbound",
                },
                file={},
                evidence=[
                    f"Inbound port scan from {remote_ip}",
                    f"Unique local ports probed: {len(unique_ports)} in {self.scan_window}s",
                ],
                metadata={"scan_threshold": self.scan_threshold},
                mitre_techniques=["T1046"],
            ))
            self.port_scan_tracker.pop(remote_ip, None)


class FileCollector(TelemetryCollector):
    """Collects file system events by polling modification times.

    Bounded on both axes: the mtime table has a cap, and the recent-change
    list is a ``deque`` with ``maxlen``.  Both were unbounded dicts/lists that
    grew for the lifetime of the process.
    """

    DEFAULT_MAX_TRACKED_FILES = 20_000

    def __init__(self, event_queue: queue.Queue, config: Dict):
        super().__init__(event_queue, config)
        self.watch_dirs = config.get("watch_dirs", [])
        self.max_tracked_files = max(
            16, int(config.get("max_tracked_files", self.DEFAULT_MAX_TRACKED_FILES))
        )
        self.last_check_times: "OrderedDict[str, float]" = OrderedDict()
        self.ransomware_window = config.get("ransomware_window", 5)
        self.ransomware_threshold = config.get("ransomware_threshold", 5)
        # Bounded history; entries also expire by time in _check_ransomware.
        self.file_modifications: "deque" = deque(maxlen=4096)
        # A full os.walk every second is far too aggressive for a large tree.
        self.poll_interval = max(1.0, float(config.get("file_poll_interval", 5.0)))
        self.max_files_per_sweep = max(
            256, int(config.get("max_files_per_sweep", 20_000))
        )

    def _collect(self):
        while self.running:
            try:
                self.poll_once()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def poll_once(self) -> int:
        """Walk the watch directories once; return the count of changes."""
        changes = 0
        scanned = 0
        for watch_dir in self.watch_dirs:
            if not os.path.exists(watch_dir):
                continue
            for root, _dirs, files in os.walk(watch_dir):
                for filename in files:
                    if scanned >= self.max_files_per_sweep:
                        return changes
                    scanned += 1
                    filepath = os.path.join(root, filename)
                    try:
                        mod_time = os.path.getmtime(filepath)
                    except OSError:
                        continue
                    previous = self.last_check_times.get(filepath)
                    self.last_check_times[filepath] = mod_time
                    self.last_check_times.move_to_end(filepath)
                    while len(self.last_check_times) > self.max_tracked_files:
                        self.last_check_times.popitem(last=False)
                    if previous is None:
                        continue
                    if mod_time > previous:
                        self._record_modification(filepath, filename)
                        changes += 1
        return changes

    def _record_modification(self, filepath: str, filename: str):
        now = time.time()
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_id=f"FILE_MODIFY_{int(now)}_{hash(filepath) % 10000}",
            category=EventCategory.FILE.value,
            severity=EventSeverity.INFO.value,
            source="FileCollector",
            host=socket.gethostname(),
            user="",
            process="",
            pid=0,
            parent_pid=0,
            command_line="",
            network={},
            file={"path": filepath, "filename": filename, "extension": os.path.splitext(filename)[1]},
            evidence=[f"File modified: {filepath}"],
            metadata={"modification_type": "modified"},
        )
        self._emit(event)
        # Store the monotonic-ish epoch alongside the record so the window
        # check does not re-parse an ISO string for every retained entry.
        self.file_modifications.append((now, filename))
        self._check_ransomware()

    def _check_ransomware(self):
        now = time.time()
        # Expire from the left: the deque is time-ordered, so this is O(expired)
        # instead of rebuilding the whole list on every single modification.
        while self.file_modifications and now - self.file_modifications[0][0] >= self.ransomware_window:
            self.file_modifications.popleft()
        recent = self.file_modifications
        if len(recent) < self.ransomware_threshold:
            return
        suspicious_extensions = {'.locked', '.encrypted', '.crypt', '.ransom'}
        suspicious_count = sum(
            1 for _ts, name in recent
            if os.path.splitext(name)[1].lower() in suspicious_extensions
        )
        if suspicious_count >= 2:
            self._emit(SecurityEvent(
                timestamp=datetime.now().isoformat(),
                event_id=f"RANSOMWARE_{int(now)}",
                category=EventCategory.FILE.value,
                severity=EventSeverity.CRITICAL.value,
                source="FileCollector",
                host=socket.gethostname(),
                user="",
                process="",
                pid=0,
                parent_pid=0,
                command_line="",
                network={},
                file={},
                evidence=[
                    f"Mass file modifications: {len(recent)} in {self.ransomware_window}s",
                    f"Suspicious extensions: {suspicious_count}",
                ],
                metadata={"ransomware_indicators": suspicious_count},
                mitre_techniques=["T1486"],
            ))
            self.file_modifications.clear()


class AuthCollector(TelemetryCollector):
    """Collects authentication events."""

    def __init__(self, event_queue: queue.Queue, config: Dict):
        super().__init__(event_queue, config)
        # Bounded, time-ordered (epoch, identity) entries.
        self.failed_logons: "deque" = deque(maxlen=4096)
        self.threshold = config.get("failed_logon_threshold", 5)
        self.window = config.get("failed_logon_window", 60)
        self.poll_interval = max(1.0, float(config.get("auth_poll_interval", 2.0)))
        self._seen_records: "deque" = deque(maxlen=8192)
        self._seen_record_set: set = set()

    def _collect(self):
        while self.running:
            handle = None
            try:
                if not WIN32_AVAILABLE:
                    time.sleep(self.poll_interval)
                    continue

                handle = win32evtlog.OpenEventLog("localhost", "Security")
                flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                while self.running:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not events:
                        break
                    for record in events:
                        event_id = record.EventID & 0xFFFF
                        if event_id in (4624, 4625, 4627):
                            self._process_auth_event(record)
            except Exception as exc:
                self.last_emit_error = f"{type(exc).__name__}: {exc}"
            finally:
                # The handle was previously leaked on every pass, one per
                # second, for the lifetime of the process.
                if handle is not None:
                    try:
                        win32evtlog.CloseEventLog(handle)
                    except Exception:
                        pass
            time.sleep(self.poll_interval)

    def _process_auth_event(self, record):
        event_id = record.EventID & 0xFFFF
        if event_id != 4625:
            return
        record_number = getattr(record, "RecordNumber", None)
        # Reading the Security log sequentially from the start on every pass
        # re-delivers records already reported. Suppress what we have seen.
        if record_number is not None:
            if record_number in self._seen_records:
                return
            self._seen_records.append(record_number)
            self._seen_record_set.add(record_number)
            while len(self._seen_record_set) > self._seen_records.maxlen:
                self._seen_record_set.discard(self._seen_records[0])
                self._seen_records.popleft()

        try:
            timestamp = record.TimeGenerated.Format()
        except Exception:
            timestamp = datetime.now().isoformat()

        self._emit(SecurityEvent(
            timestamp=timestamp,
            event_id=f"FAILED_LOGON_{record_number}",
            category=EventCategory.AUTH.value,
            severity=EventSeverity.MEDIUM.value,
            source="AuthCollector",
            host=getattr(record, "ComputerName", socket.gethostname()),
            user="",
            process="",
            pid=0,
            parent_pid=0,
            command_line="",
            network={},
            file={},
            evidence=[f"Failed logon attempt #{record_number}"],
            metadata={"logon_type": "unknown"},
        ))
        self.record_failed_logon(str(record_number))

    def record_failed_logon(self, identity: str) -> None:
        """Register one failed logon, then evaluate the brute-force rule.

        ``failed_logons`` was never written to, so ``_check_brute_force``
        always compared ``len({}) >= threshold`` and the rule could never
        fire. Each attempt now contributes a timestamped entry.
        """
        self.failed_logons.append((time.time(), identity))
        self._check_brute_force()

    def _check_brute_force(self):
        now = time.time()
        cutoff = now - self.window
        while self.failed_logons and self.failed_logons[0][0] <= cutoff:
            self.failed_logons.popleft()

        if len(self.failed_logons) >= self.threshold:
            count = len(self.failed_logons)
            self._emit(SecurityEvent(
                timestamp=datetime.now().isoformat(),
                event_id=f"BRUTE_FORCE_{int(now)}",
                category=EventCategory.AUTH.value,
                severity=EventSeverity.HIGH.value,
                source="AuthCollector",
                host=socket.gethostname(),
                user="",
                process="",
                pid=0,
                parent_pid=0,
                command_line="",
                network={},
                file={},
                evidence=[
                    f"Multiple failed logons: {count} in {self.window}s",
                    f"Threshold: {self.threshold}",
                ],
                metadata={"failed_count": count},
                mitre_techniques=["T1110.001"],
            ))
            # Reset so one burst reports once instead of on every new attempt.
            self.failed_logons.clear()


class TelemetryEngine:
    """Central telemetry collection engine."""

    DEFAULT_QUEUE_CAPACITY = 10_000

    def __init__(self, config: Dict):
        self.config = config
        # A bounded queue is required: an unbounded one lets a slow or absent
        # consumer grow the process heap until it is killed.
        capacity = max(1, int(config.get("queue_capacity", self.DEFAULT_QUEUE_CAPACITY)))
        self.event_queue = queue.Queue(maxsize=capacity)
        self.collectors = []
        self.running = False

    def register_collector(self, collector: TelemetryCollector):
        self.collectors.append(collector)

    def start(self):
        self.running = True
        for collector in self.collectors:
            collector.start()

    def stop(self):
        self.running = False
        for collector in self.collectors:
            collector.stop()

    def get_dropped_events(self) -> int:
        """Total events discarded by backpressure across all collectors."""
        return sum(getattr(c, "dropped_events", 0) for c in self.collectors)

    def get_events(self, timeout: float = 0.1, limit: int = 1000) -> List[SecurityEvent]:
        """Drain up to ``limit`` events so one call cannot spin forever."""
        events = []
        try:
            while len(events) < max(1, int(limit)):
                events.append(self.event_queue.get(timeout=timeout))
        except queue.Empty:
            pass
        return events
