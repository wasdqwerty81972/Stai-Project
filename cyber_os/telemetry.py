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
from datetime import datetime
from typing import Dict, List, Any, Optional
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

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._collect, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _collect(self):
        raise NotImplementedError

    def _emit(self, event: SecurityEvent):
        try:
            self.event_queue.put(event)
        except Exception:
            pass


class ProcessCollector(TelemetryCollector):
    """Collects process creation and termination events."""

    def __init__(self, event_queue: queue.Queue, config: Dict):
        super().__init__(event_queue, config)
        self.known_processes = {}
        self.suspicious_chains = config.get("suspicious_chains", [
            ("winword.exe", "cmd.exe"),
            ("excel.exe", "powershell.exe"),
            ("outlook.exe", "cmd.exe"),
            ("chrome.exe", "powershell.exe"),
            ("firefox.exe", "cmd.exe"),
            ("msedge.exe", "powershell.exe"),
        ])

    def _collect(self):
        while self.running:
            try:
                if not PSUTIL_AVAILABLE:
                    time.sleep(2)
                    continue

                for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline', 'create_time', 'username']):
                    try:
                        pid = proc.info['pid']
                        name = (proc.info['name'] or "").lower()
                        
                        if pid not in self.known_processes:
                            self.known_processes[pid] = proc.info
                            event = SecurityEvent(
                                timestamp=datetime.now().isoformat(),
                                event_id=f"PROCESS_CREATE_{pid}",
                                category=EventCategory.PROCESS.value,
                                severity=EventSeverity.INFO.value,
                                source="ProcessCollector",
                                host=socket.gethostname(),
                                user=proc.info.get('username', 'unknown'),
                                process=name,
                                pid=pid,
                                parent_pid=proc.info.get('ppid', 0),
                                command_line=" ".join(proc.info['cmdline']) if proc.info['cmdline'] else "",
                                network={},
                                file={"path": proc.info.get('exe', '')},
                                evidence=[f"Process created: {name} (PID: {pid})"],
                                metadata={"create_time": proc.info.get('create_time', 0)},
                            )
                            self._emit(event)
                            self._check_suspicious_chain(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                pass
            time.sleep(2)

    def _check_suspicious_chain(self, proc):
        try:
            parent = proc.parent()
            if parent:
                parent_name = parent.name().lower()
                child_name = proc.name().lower()
                for suspicious_parent, suspicious_child in self.suspicious_chains:
                    if parent_name == suspicious_parent and child_name == suspicious_child:
                        event = SecurityEvent(
                            timestamp=datetime.now().isoformat(),
                            event_id=f"SUSPICIOUS_CHAIN_{proc.pid}",
                            category=EventCategory.PROCESS.value,
                            severity=EventSeverity.HIGH.value,
                            source="ProcessCollector",
                            host=socket.gethostname(),
                            user="",
                            process=child_name,
                            pid=proc.pid,
                            parent_pid=parent.pid,
                            command_line=" ".join(proc.cmdline()) if proc.cmdline() else "",
                            network={},
                            file={},
                            evidence=[
                                f"Suspicious parent-child: {parent_name} -> {child_name}",
                                f"Parent PID: {parent.pid}",
                                f"Child PID: {proc.pid}",
                            ],
                            metadata={"chain": f"{parent_name} -> {child_name}"},
                            mitre_techniques=["T1059.001"],
                        )
                        self._emit(event)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


class NetworkCollector(TelemetryCollector):
    """Collects network connection events."""

    def __init__(self, event_queue: queue.Queue, config: Dict):
        super().__init__(event_queue, config)
        self.port_scan_tracker = {}
        self.scan_threshold = config.get("port_scan_threshold", 10)
        self.scan_window = config.get("port_scan_window", 30)

    def _collect(self):
        while self.running:
            try:
                if not PSUTIL_AVAILABLE:
                    time.sleep(1)
                    continue

                connections = psutil.net_connections(kind='inet')
                for conn in connections:
                    if conn.laddr and conn.raddr:
                        local_ip, local_port = conn.laddr
                        remote_ip, remote_port = conn.raddr
                        pid = conn.pid if conn.pid else 0
                        
                        event = SecurityEvent(
                            timestamp=datetime.now().isoformat(),
                            event_id=f"NETWORK_CONN_{local_port}_{remote_port}_{int(time.time())}",
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
                                "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                                "status": conn.status,
                            },
                            file={},
                            evidence=[f"Connection: {local_ip}:{local_port} -> {remote_ip}:{remote_port}"],
                            metadata={"connection_state": conn.status},
                        )
                        self._emit(event)
                        self._check_port_scan(remote_ip, remote_port)
            except Exception as e:
                pass
            time.sleep(1)

    def _check_port_scan(self, remote_ip: str, remote_port: int):
        now = time.time()
        if remote_ip not in self.port_scan_tracker:
            self.port_scan_tracker[remote_ip] = []
        
        self.port_scan_tracker[remote_ip].append((now, remote_port))
        
        cutoff = now - self.scan_window
        self.port_scan_tracker[remote_ip] = [(t, p) for t, p in self.port_scan_tracker[remote_ip] if t > cutoff]
        
        unique_ports = set(p for _, p in self.port_scan_tracker[remote_ip])
        if len(unique_ports) >= self.scan_threshold:
            event = SecurityEvent(
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
                network={"remote_ip": remote_ip, "scanned_ports": list(unique_ports)[:20]},
                file={},
                evidence=[
                    f"Port scan detected from {remote_ip}",
                    f"Unique ports: {len(unique_ports)} in {self.scan_window}s",
                ],
                metadata={"scan_threshold": self.scan_threshold},
                mitre_techniques=["T1046"],
            )
            self._emit(event)
            self.port_scan_tracker[remote_ip].clear()


class FileCollector(TelemetryCollector):
    """Collects file system events."""

    def __init__(self, event_queue: queue.Queue, config: Dict):
        super().__init__(event_queue, config)
        self.watch_dirs = config.get("watch_dirs", [])
        self.last_check_times = {}
        self.ransomware_window = config.get("ransomware_window", 5)
        self.ransomware_threshold = config.get("ransomware_threshold", 5)
        self.file_modifications = []

    def _collect(self):
        while self.running:
            try:
                for watch_dir in self.watch_dirs:
                    if not os.path.exists(watch_dir):
                        continue
                    for root, dirs, files in os.walk(watch_dir):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            try:
                                mod_time = os.path.getmtime(filepath)
                                now = time.time()
                                
                                if filepath not in self.last_check_times:
                                    self.last_check_times[filepath] = mod_time
                                    continue
                                
                                if mod_time > self.last_check_times[filepath]:
                                    self.last_check_times[filepath] = mod_time
                                    self._record_modification(filepath, filename)
                            except Exception:
                                continue
            except Exception:
                pass
            time.sleep(1)

    def _record_modification(self, filepath: str, filename: str):
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_id=f"FILE_MODIFY_{int(time.time())}_{hash(filepath) % 10000}",
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
        self.file_modifications.append(event)
        self._check_ransomware()

    def _check_ransomware(self):
        now = time.time()
        recent = [e for e in self.file_modifications if now - datetime.fromisoformat(e.timestamp).timestamp() < self.ransomware_window]
        
        if len(recent) >= self.ransomware_threshold:
            suspicious_extensions = {'.locked', '.encrypted', '.crypt', '.ransom'}
            suspicious_count = sum(1 for e in recent if os.path.splitext(e.file.get('filename', ''))[1].lower() in suspicious_extensions)
            
            if suspicious_count >= 2:
                event = SecurityEvent(
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
                )
                self._emit(event)
                self.file_modifications.clear()


class AuthCollector(TelemetryCollector):
    """Collects authentication events."""

    def __init__(self, event_queue: queue.Queue, config: Dict):
        super().__init__(event_queue, config)
        self.failed_logons = {}
        self.threshold = config.get("failed_logon_threshold", 5)
        self.window = config.get("failed_logon_window", 60)

    def _collect(self):
        while self.running:
            try:
                if not WIN32_AVAILABLE:
                    time.sleep(2)
                    continue

                hand = win32evtlog.OpenEventLog("localhost", "Security")
                flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                while self.running and events:
                    for event in events:
                        event_id = event.EventID & 0xFFFF
                        if event_id in [4624, 4625, 4627]:
                            self._process_auth_event(event)
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
            except Exception:
                pass
            time.sleep(1)

    def _process_auth_event(self, event):
        event_id = event.EventID & 0xFFFF
        timestamp = event.TimeGenerated.Format()
        
        if event_id == 4625:
            event = SecurityEvent(
                timestamp=timestamp,
                event_id=f"FAILED_LOGON_{event.RecordNumber}",
                category=EventCategory.AUTH.value,
                severity=EventSeverity.MEDIUM.value,
                source="AuthCollector",
                host=event.ComputerName,
                user="",
                process="",
                pid=0,
                parent_pid=0,
                command_line="",
                network={},
                file={},
                evidence=[f"Failed logon attempt #{event.RecordNumber}"],
                metadata={"logon_type": "unknown"},
            )
            self._emit(event)
            self._check_brute_force()

    def _check_brute_force(self):
        now = time.time()
        cutoff = now - self.window
        self.failed_logons = {k: v for k, v in self.failed_logons.items() if v > cutoff}
        
        if len(self.failed_logons) >= self.threshold:
            event = SecurityEvent(
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
                    f"Multiple failed logons: {len(self.failed_logons)} in {self.window}s",
                    f"Threshold: {self.threshold}",
                ],
                metadata={"failed_count": len(self.failed_logons)},
                mitre_techniques=["T1110.001"],
            )
            self._emit(event)


class TelemetryEngine:
    """Central telemetry collection engine."""

    def __init__(self, config: Dict):
        self.config = config
        self.event_queue = queue.Queue()
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

    def get_events(self, timeout: float = 0.1) -> List[SecurityEvent]:
        events = []
        try:
            while True:
                events.append(self.event_queue.get(timeout=timeout))
        except queue.Empty:
            pass
        return events
