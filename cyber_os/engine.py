"""
CyberOS Live Defense Engine
Autonomous cyber defense system with real-time monitoring, detection, and response.
"""

import os
import sys
import json
import time
import queue
import threading
import hashlib
import subprocess
import socket
import re
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum

from cyber_os.correlation_engine import CorrelationEngine
from cyber_os.incident_manager import IncidentManager
from cyber_os.approval_engine import ApprovalEngine
from cyber_os.sensors import SensorEvent, WindowsSensorService
from ui.event_bus import AgentEvent, event_bus

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(Enum):
    FAILED_LOGON = "failed_logon"
    SUCCESSFUL_LOGON = "successful_logon"
    PROCESS_CREATION = "process_creation"
    POWERSHELL_EXECUTION = "powershell_execution"
    NETWORK_CONNECTION = "network_connection"
    FILE_MODIFICATION = "file_modification"
    SERVICE_INSTALLATION = "service_installation"
    REGISTRY_MODIFICATION = "registry_modification"


@dataclass
class SecurityEvent:
    timestamp: str
    event_type: str
    severity: str
    source: str
    details: Dict[str, Any]
    mitre_technique: Optional[str] = None
    event_id: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class ThreatAlert:
    timestamp: str
    alert_type: str
    severity: str
    mitre_technique: str
    technique_name: str
    summary: str
    evidence: List[str]
    ai_reasoning: str
    blast_radius: str
    threat_score: int
    recommended_actions: List[str]
    autonomous_action_taken: bool = False
    actions_taken: List[str] = field(default_factory=list)
    verification: str = ""
    event_id: str = ""

    def to_dict(self):
        return asdict(self)


class EventMonitor:
    """Monitors Windows Event Logs for security events."""

    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue
        self.running = False
        self.monitor_thread = None
        self.last_event_times = defaultdict(list)

    def start(self):
        if not WIN32_AVAILABLE:
            print("[!] EventMonitor requires pywin32. Event log monitoring disabled.")
            return
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        self.running = False

    def _monitor_loop(self):
        """Monitor Security, System, and PowerShell logs."""
        if not WIN32_AVAILABLE:
            return

        try:
            hand = win32evtlog.OpenEventLog("localhost", "Security")
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)

            while self.running and events:
                for event in events:
                    if not self.running:
                        break
                    event_id = event.EventID & 0xFFFF
                    if event_id in [4624, 4625, 4688, 4697, 7045, 4104]:
                        self.event_queue.put(self._convert_event(event))
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                time.sleep(0.1)
        except Exception as e:
            print(f"[!] EventMonitor error: {e}")

    def _convert_event(self, event) -> SecurityEvent:
        event_id = event.EventID & 0xFFFF
        event_type_map = {
            # 4624 is a *successful* logon. Mapping it to FAILED_LOGON inflated the
            # brute-force counter in _check_brute_force, which filters on event_type.
            4624: EventType.SUCCESSFUL_LOGON.value,
            4625: EventType.FAILED_LOGON.value,
            4688: EventType.PROCESS_CREATION.value,
            4697: EventType.SERVICE_INSTALLATION.value,
            7045: EventType.SERVICE_INSTALLATION.value,
            4104: EventType.POWERSHELL_EXECUTION.value,
        }
        severity_map = {
            4624: Severity.INFO.value,
            4625: Severity.MEDIUM.value,
            4688: Severity.INFO.value,
            4697: Severity.HIGH.value,
            7045: Severity.HIGH.value,
            4104: Severity.INFO.value,
        }

        return SecurityEvent(
            timestamp=event.TimeGenerated.Format(),
            event_type=event_type_map.get(event_id, "unknown"),
            severity=severity_map.get(event_id, Severity.INFO.value),
            source="Windows Event Log",
            details={
                "event_id": event_id,
                "record_number": event.RecordNumber,
                "computer": event.ComputerName,
                "message": str(event.StringInserts),
            },
            event_id=str(event_id),
        )


class NetworkMonitor:
    """Monitors network connections for port scanning and suspicious activity."""

    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue
        self.running = False
        self.monitor_thread = None
        self.connection_history = deque(maxlen=1000)
        self.port_scan_tracker = defaultdict(list)

    def start(self):
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        self.running = False

    def _monitor_loop(self):
        """Poll network connections every second."""
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
                            event_type=EventType.NETWORK_CONNECTION.value,
                            severity=Severity.INFO.value,
                            source="NetworkMonitor",
                            details={
                                "local_addr": f"{local_ip}:{local_port}",
                                "remote_addr": f"{remote_ip}:{remote_port}",
                                "pid": pid,
                                "status": conn.status,
                            },
                        )
                        self.event_queue.put(event)
                        self.connection_history.append(event)
                        
                        # Port scan detection
                        self._check_port_scan(remote_ip, remote_port, pid)
            except Exception as e:
                print(f"[!] NetworkMonitor error: {e}")
            time.sleep(1)

    def _check_port_scan(self, remote_ip: str, remote_port: int, pid: int):
        """Detect port scanning patterns."""
        now = datetime.now()
        self.port_scan_tracker[remote_ip].append((now, remote_port))
        
        cutoff = now - timedelta(seconds=30)
        self.port_scan_tracker[remote_ip] = [
            (t, p) for t, p in self.port_scan_tracker[remote_ip] if t > cutoff
        ]
        
        unique_ports = set(p for _, p in self.port_scan_tracker[remote_ip])
        if len(unique_ports) >= 10:
            alert = ThreatAlert(
                timestamp=now.isoformat(),
                alert_type="port_scan",
                severity=Severity.HIGH.value,
                mitre_technique="T1046",
                technique_name="Network Service Scanning",
                summary=f"Port scan detected from {remote_ip}: {len(unique_ports)} unique ports in 30s",
                evidence=[
                    f"Source IP: {remote_ip}",
                    f"Unique ports scanned: {len(unique_ports)}",
                    f"Sample ports: {list(unique_ports)[:10]}",
                ],
                ai_reasoning=f"System detected {len(unique_ports)} unique port connections from {remote_ip} within 30 seconds. This is a classic port scanning pattern used for reconnaissance.",
                blast_radius="Attacker has mapped open ports and can now target specific services for exploitation.",
                threat_score=7,
                recommended_actions=["Block source IP", "Alert SOC", "Review firewall rules"],
                event_id=f"PORTSCAN-{remote_ip}-{int(now.timestamp())}",
            )
            self.event_queue.put(alert)
            self.port_scan_tracker[remote_ip].clear()


class ProcessMonitor:
    """Monitors process creation and suspicious parent-child relationships."""

    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue
        self.running = False
        self.monitor_thread = None
        self.known_processes = {}
        self.suspicious_chains = [
            ("winword.exe", "cmd.exe"),
            ("excel.exe", "powershell.exe"),
            ("outlook.exe", "cmd.exe"),
            ("chrome.exe", "powershell.exe"),
            ("firefox.exe", "cmd.exe"),
        ]

    def start(self):
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        self.running = False

    def _monitor_loop(self):
        """Poll processes every 2 seconds."""
        while self.running:
            try:
                if not PSUTIL_AVAILABLE:
                    time.sleep(2)
                    continue
                    
                for proc in psutil.process_iter(['pid', 'name', 'ppid', 'cmdline', 'create_time']):
                    try:
                        pid = proc.info['pid']
                        name = proc.info['name'].lower() if proc.info['name'] else ""
                        
                        if pid not in self.known_processes:
                            self.known_processes[pid] = proc.info
                            event = SecurityEvent(
                                timestamp=datetime.now().isoformat(),
                                event_type=EventType.PROCESS_CREATION.value,
                                severity=Severity.INFO.value,
                                source="ProcessMonitor",
                                details={
                                    "pid": pid,
                                    "name": name,
                                    "ppid": proc.info['ppid'],
                                    "cmdline": " ".join(proc.info['cmdline']) if proc.info['cmdline'] else "",
                                },
                            )
                            self.event_queue.put(event)
                            self._check_suspicious_chain(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                print(f"[!] ProcessMonitor error: {e}")
            time.sleep(2)

    def _check_suspicious_chain(self, proc):
        """Check if process has suspicious parent."""
        try:
            parent = proc.parent()
            if parent:
                parent_name = parent.name().lower()
                child_name = proc.name().lower()
                for suspicious_parent, suspicious_child in self.suspicious_chains:
                    if parent_name == suspicious_parent and child_name == suspicious_child:
                        alert = ThreatAlert(
                            timestamp=datetime.now().isoformat(),
                            alert_type="suspicious_process_chain",
                            severity=Severity.HIGH.value,
                            mitre_technique="T1059.001",
                            technique_name="Command and Scripting Interpreter",
                            summary=f"Suspicious process chain: {parent_name} → {child_name}",
                            evidence=[
                                f"Parent: {parent_name} (PID: {parent.pid})",
                                f"Child: {child_name} (PID: {proc.pid})",
                            ],
                            ai_reasoning=f"A {parent_name} process spawned {child_name}, which is unusual. This pattern is commonly associated with malware using Office applications as a dropper.",
                            blast_radius="Potential code execution, file download, or lateral movement from compromised Office document.",
                            threat_score=7,
                            recommended_actions=["Terminate child process", "Scan parent document", "Check for macros"],
                            event_id=f"PROCCHAIN-{proc.pid}-{int(time.time())}",
                        )
                        self.event_queue.put(alert)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


class FileSystemMonitor:
    """Monitors file system for ransomware-like behavior."""

    def __init__(self, event_queue: queue.Queue, watch_dirs: List[str]):
        self.event_queue = event_queue
        self.watch_dirs = watch_dirs
        self.running = False
        self.monitor_thread = None
        self.file_modifications = deque(maxlen=1000)
        self.last_check_times = {}

    def start(self):
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        self.running = False

    def _monitor_loop(self):
        """Poll watched directories for changes."""
        while self.running:
            try:
                for watch_dir in self.watch_dirs:
                    if not os.path.exists(watch_dir):
                        continue
                    for root, dirs, files in os.walk(watch_dir):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            mod_time = os.path.getmtime(filepath)
                            now = time.time()
                            
                            if filepath not in self.last_check_times:
                                self.last_check_times[filepath] = mod_time
                                continue
                            
                            if mod_time > self.last_check_times[filepath]:
                                self.last_check_times[filepath] = mod_time
                                self._record_modification(filepath, filename)
            except Exception as e:
                print(f"[!] FileSystemMonitor error: {e}")
            time.sleep(1)

    def _record_modification(self, filepath: str, filename: str):
        """Record file modification and check for ransomware patterns."""
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type=EventType.FILE_MODIFICATION.value,
            severity=Severity.INFO.value,
            source="FileSystemMonitor",
            details={
                "filepath": filepath,
                "filename": filename,
                "extension": os.path.splitext(filename)[1],
            },
        )
        self.event_queue.put(event)
        self.file_modifications.append(event)
        self._check_ransomware_pattern()

    def _check_ransomware_pattern(self):
        """Check for ransomware-like behavior."""
        now = datetime.now()
        recent = [
            e for e in self.file_modifications
            if (now - datetime.fromisoformat(e.timestamp)).total_seconds() < 5
        ]
        
        if len(recent) >= 5:
            suspicious_extensions = {'.locked', '.encrypted', '.crypt', '.ransom'}
            suspicious_count = sum(
                1 for e in recent
                if os.path.splitext(e.details.get('filename', ''))[1].lower() in suspicious_extensions
            )
            
            if suspicious_count >= 2:
                alert = ThreatAlert(
                    timestamp=now.isoformat(),
                    alert_type="ransomware_behavior",
                    severity=Severity.CRITICAL.value,
                    mitre_technique="T1486",
                    technique_name="Data Encrypted for Impact",
                    summary=f"Ransomware behavior detected: {len(recent)} files modified in 5s",
                    evidence=[
                        f"Files modified: {len(recent)}",
                        f"Suspicious extensions: {suspicious_count}",
                        f"Sample files: {[e.details.get('filename') for e in recent[:5]]}",
                    ],
                    ai_reasoning=f"System detected {len(recent)} file modifications within 5 seconds, with {suspicious_count} files showing ransomware-like extensions.",
                    blast_radius="All monitored files could be encrypted. Data loss and operational disruption.",
                    threat_score=9,
                    recommended_actions=["Terminate malicious process", "Restore from backup", "Block responsible executable"],
                    event_id=f"RANSOMWARE-{int(now.timestamp())}",
                )
                self.event_queue.put(alert)
                self.file_modifications.clear()


class PowerShellMonitor:
    """Monitors PowerShell execution for obfuscation."""

    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue
        self.running = False
        self.monitor_thread = None

    def start(self):
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

    def stop(self):
        self.running = False

    def _monitor_loop(self):
        """Poll for PowerShell processes and check for obfuscation."""
        while self.running:
            try:
                if not PSUTIL_AVAILABLE:
                    time.sleep(2)
                    continue
                    
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        if proc.info['name'] and 'powershell' in proc.info['name'].lower():
                            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                            if self._is_obfuscated(cmdline):
                                alert = ThreatAlert(
                                    timestamp=datetime.now().isoformat(),
                                    alert_type="powershell_obfuscation",
                                    severity=Severity.HIGH.value,
                                    mitre_technique="T1059.001",
                                    technique_name="PowerShell Execution",
                                    summary=f"Obfuscated PowerShell detected: PID {proc.info['pid']}",
                                    evidence=[
                                        f"Process: {proc.info['name']}",
                                        f"PID: {proc.info['pid']}",
                                        f"Command: {cmdline[:200]}",
                                    ],
                                    ai_reasoning=f"PowerShell process executed with obfuscation indicators: {', '.join(self._get_obfuscation_indicators(cmdline))}. Common malware delivery technique.",
                                    blast_radius="Potential code execution, file download, credential theft, or lateral movement.",
                                    threat_score=8,
                                    recommended_actions=["Terminate process", "Block URLs", "Quarantine files"],
                                    event_id=f"POWERSHELL-{proc.info['pid']}-{int(time.time())}",
                                )
                                self.event_queue.put(alert)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                print(f"[!] PowerShellMonitor error: {e}")
            time.sleep(2)

    def _is_obfuscated(self, cmdline: str) -> bool:
        """Check if PowerShell command contains obfuscation indicators."""
        obfuscation_patterns = [
            r'-EncodedCommand',
            r'FromBase64String',
            r'ToBase64String',
            r'IEX\s*\(',
            r'Invoke-Expression',
            r'DownloadString',
            r'DownloadFile',
            r'WebClient',
            r'Net\.WebClient',
            r'\[System\.Convert\]',
            r'\[System\.Text\.Encoding\]',
        ]
        for pattern in obfuscation_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                return True
        return False

    def _get_obfuscation_indicators(self, cmdline: str) -> List[str]:
        """Get list of obfuscation indicators found."""
        indicators = []
        patterns = {
            'EncodedCommand': r'-EncodedCommand',
            'FromBase64String': r'FromBase64String',
            'IEX': r'IEX\s*\(',
            'Invoke-Expression': r'Invoke-Expression',
            'DownloadString': r'DownloadString',
        }
        for name, pattern in patterns.items():
            if re.search(pattern, cmdline, re.IGNORECASE):
                indicators.append(name)
        return indicators


class CyberOSEngine:
    """Core CyberOS engine: coordinates monitoring, detection, and response."""

    def __init__(self, config_path: str = "cyber_os_config.json"):
        self.config = self._load_config(config_path)
        self.running = False
        self.threat_score = 0
        self.events = deque(maxlen=1000)
        self.alerts = deque(maxlen=500)
        self.actions_log = deque(maxlen=500)
        
        # Thread-safe queues
        self.monitor_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self.action_queue = queue.Queue()
        self.ui_queue = queue.Queue()
        self.event_index: Dict[str, Any] = {}
        self.correlation = CorrelationEngine(self.event_index)
        self.incident_manager = IncidentManager()
        self._sensor_event_lock = threading.RLock()
        self._response_approval_lock = threading.RLock()
        self._pending_response_approvals: Dict[str, ThreatAlert] = {}
        self._approved_response_ids: set[str] = set()
        self.approval_engine = ApprovalEngine()
        self.sensor_service = WindowsSensorService(
            callback=self._handle_sensor_event,
            database_path=os.path.join("cyber_db", "windows_sensor_queue.sqlite3"),
            privacy=self.config.get("sensor_privacy", {}),
        )
        
        # Monitors
        self.event_monitor = EventMonitor(self.monitor_queue)
        self.network_monitor = NetworkMonitor(self.monitor_queue)
        self.process_monitor = ProcessMonitor(self.monitor_queue)
        self.file_monitor = FileSystemMonitor(
            self.monitor_queue,
            self.config.get("watch_dirs", ["C:\\AEGIS_Test"])
        )
        self.powershell_monitor = PowerShellMonitor(self.monitor_queue)
        
        # Response tracking
        self.blocked_ips = set()
        self.blocked_ports = set()
        self.terminated_pids = set()
        self.quarantined_files = []
        self.locked_accounts = set()

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file."""
        default_config = {
            "watch_dirs": ["C:\\AEGIS_Test"],
            "quarantine_dir": "C:\\AEGIS_Quarantine",
            "thresholds": {
                "failed_logons": 5,
                "failed_logon_window": 60,
                "port_scan_ports": 10,
                "port_scan_window": 30,
                "ransomware_files": 5,
                "ransomware_window": 2,
            },
            "auto_response": {
                "high_threat": True,
                "critical_threat": True,
                # Containment actions are always gated by an explicit approval
                # request, even when an older config says otherwise.
                "require_approval": True,
            },
            "sensor_privacy": {
                "collect_file_paths": False,
                "collect_dns_names": False,
                "collect_command_lines": False,
            },
        }
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    loaded = json.load(f)
                    default_config.update(loaded)
            except Exception as e:
                print(f"[!] Failed to load config: {e}")
        
        return default_config

    def start(self):
        """Start endpoint collection and the event/response workers once."""
        if self.running:
            return False
        self.running = True
        # WindowsSensorService is the sole active collector for the Phase 1
        # Windows Event Log sources. The older polling monitors remain
        # constructible for compatibility, but are not started because they
        # duplicate process, network, file, and Security-log telemetry.
        self.sensor_service.start()
        self._detection_thread = threading.Thread(target=self._detection_loop, name="cyberos-detection", daemon=True)
        self._response_thread = threading.Thread(target=self._response_loop, name="cyberos-response", daemon=True)
        self._detection_thread.start()
        self._response_thread.start()
        self._publish_ui_event("cyberos_engine_status", "CyberOS sensor collection started", "started")
        return True

    def stop(self):
        """Stop endpoint collection and engine workers idempotently."""
        if not self.running:
            self.sensor_service.stop()
            return False
        self.sensor_service.stop()
        self.running = False
        for name in ("_detection_thread", "_response_thread"):
            thread = getattr(self, name, None)
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=2.0)
        self._publish_ui_event("cyberos_engine_status", "CyberOS sensor collection stopped", "stopped")
        return True

    def _detection_loop(self):
        """Consume monitor events, apply detection rules, emit alerts."""
        while self.running:
            try:
                event = self.monitor_queue.get(timeout=0.1)
                self.events.append(event)
                self._ingest_telemetry_event(event)
                
                # Apply detection rules
                alert = self._apply_detection_rules(event)
                if alert:
                    self.alerts.append(alert)
                    self.alert_queue.put(alert)
                    self.ui_queue.put(alert)
                    self._update_threat_score(alert.threat_score)
            except queue.Empty:
                continue

    def _ingest_telemetry_event(self, event: Any) -> None:
        """Normalize native monitor output into correlation, incidents, and UI events."""
        event_id = str(getattr(event, "event_id", None) or f"telemetry-{id(event)}")
        self.event_index[event_id] = event
        payload = event.to_dict() if hasattr(event, "to_dict") else {"event_id": event_id, "message": str(event)}
        event_type = getattr(event, "event_type", "telemetry")
        self._publish_ui_event("telemetry_event", f"Telemetry: {event_type}", "observed", event=payload)

        if isinstance(event, ThreatAlert):
            correlation = {
                "title": event.summary,
                "severity": event.severity,
                "correlation_type": event.alert_type,
                "related_events": [event_id],
                "confidence": min(1.0, event.threat_score / 10),
                "evidence": event.evidence,
                "risk_score": event.threat_score * 10,
                "mitre_technique": event.mitre_technique,
                "entities": {},
            }
        else:
            details = getattr(event, "details", {})
            category = getattr(event, "category", None)
            if hasattr(category, "value"):
                category = category.value
            if not category:
                category = "process" if event_type == EventType.PROCESS_CREATION.value else "network" if event_type == EventType.NETWORK_CONNECTION.value else "file" if event_type == EventType.FILE_MODIFICATION.value else "auth" if event_type == EventType.FAILED_LOGON.value else "security"
            file_details = dict(getattr(event, "file", {}) or {})
            if details.get("filepath"):
                file_details.setdefault("path", details["filepath"])
                file_details.setdefault("filename", details.get("filename", ""))
            elif details.get("path_hash"):
                file_details.setdefault("path", f"sha256:{details['path_hash']}")
            if not file_details.get("path") and file_details.get("path_hash"):
                file_details["path"] = f"sha256:{file_details['path_hash']}"
            network_details = dict(getattr(event, "network", {}) or {})
            normalized = {
                "event_id": event_id,
                "category": category,
                "timestamp": getattr(event, "timestamp", ""),
                "process": getattr(event, "process", "") or details.get("name", ""),
                "pid": getattr(event, "pid", 0) or details.get("pid", 0),
                "parent_pid": getattr(event, "parent_pid", 0) or details.get("ppid", 0),
                "command_line": getattr(event, "command_line", "") or details.get("cmdline", ""),
                "user": getattr(event, "user", "") or details.get("target_user_hash", ""),
                "remote_ip": getattr(event, "remote_ip", "") or details.get("remote_ip", ""),
                "network": network_details,
                "file": file_details,
            }
            correlation = None
            findings = self.correlation.add_event(normalized)
            if findings:
                correlation = findings[-1]

        if correlation:
            incident = self.incident_manager.ingest_correlated_finding(correlation, self.event_index)
            self._publish_ui_event(
                "incident_created",
                incident.title,
                "detected",
                incident_id=incident.incident_id,
                finding_ids=incident.findings,
                related_events=incident.events,
                attack_chain=incident.attack_chain,
                mitre_techniques=incident.mitre_techniques,
                severity=incident.severity,
            )

    @staticmethod
    def _publish_ui_event(event_type: str, message: str, status: str = "", **data: Any) -> None:
        event_bus.publish(AgentEvent(type=event_type, source="cyberos_engine", status=status, message=message, data=data))

    def _handle_sensor_event(self, event: SensorEvent) -> None:
        """Feed one durable sensor event through correlation and SOC triage."""
        if not self.running:
            raise RuntimeError("CyberOSEngine is stopped; retain the sensor event for the next start")
        with self._sensor_event_lock:
            if event.event_id in self.event_index:
                return
            self.events.append(event)
            self._ingest_telemetry_event(event)
            alert = self._apply_detection_rules(event)
            if alert:
                self.alerts.append(alert)
                self.alert_queue.put(alert)
                self.ui_queue.put(alert)
                self._update_threat_score(alert.threat_score)

    def _apply_detection_rules(self, event: SecurityEvent) -> Optional[ThreatAlert]:
        """Apply detection rules to an event."""
        if isinstance(event, ThreatAlert):
            return event
        
        event_type = event.event_type
        
        if event_type == EventType.FAILED_LOGON.value:
            return self._check_brute_force(event)
        
        return None

    def _check_brute_force(self, event: SecurityEvent) -> Optional[ThreatAlert]:
        """Check for brute force pattern in failed logons."""
        details = event.details
        event_id = details.get("event_id")
        
        if event_id not in {4625, "4625"} and details.get("windows_event_id") not in {4625, "4625"}:
            return None
        
        # Track failed logons from source IP
        # For demo, we'll use a simplified approach
        now = datetime.now(timezone.utc)
        now_epoch = now.timestamp()
        window_seconds = self.config["thresholds"]["failed_logon_window"]
        
        recent_failures = [
            e for e in self.events
            if (getattr(e, "event_type", "") == EventType.FAILED_LOGON.value and
                0 <= now_epoch - CorrelationEngine._timestamp_epoch(getattr(e, "timestamp", "")) < window_seconds)
        ]
        
        if len(recent_failures) >= self.config["thresholds"]["failed_logons"]:
            return ThreatAlert(
                timestamp=now.isoformat(),
                alert_type="brute_force",
                severity=Severity.HIGH.value,
                mitre_technique="T1110.001",
                technique_name="Password Spraying / Brute Force",
                summary=f"Brute force detected: {len(recent_failures)} failed logons in {window_seconds}s",
                evidence=[
                    f"Failed logons: {len(recent_failures)}",
                    f"Time window: {window_seconds} seconds",
                    f"Event IDs: {[e.details.get('event_id') for e in recent_failures[:5]]}",
                ],
                ai_reasoning=f"System detected {len(recent_failures)} failed logon attempts within {window_seconds} seconds. This pattern indicates an automated password spraying or brute force attack.",
                blast_radius="If successful, attacker gains unauthorized access to the system.",
                threat_score=8,
                recommended_actions=["Block source IP", "Lock target account", "Alert SOC"],
                event_id=f"BRUTEFORCE-{int(now.timestamp())}",
            )
        
        return None

    def _update_threat_score(self, delta: int):
        """Update overall threat score."""
        self.threat_score = min(10, max(0, self.threat_score + delta))

    def _response_loop(self):
        """Turn high-risk alerts into approval requests; never auto-contain."""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=0.1)

                if alert.threat_score >= 8:
                    self._request_response_approval(alert)
            except queue.Empty:
                continue

    def _request_response_approval(self, alert: ThreatAlert) -> str:
        """Publish a review request without performing containment actions."""
        request_seed = f"{alert.event_id}:{alert.alert_type}:{time.time_ns()}"
        approval_id = f"response-{hashlib.sha256(request_seed.encode('utf-8')).hexdigest()[:16]}"
        if not self.approval_engine.register_pending_request(approval_id):
            return ""
        with self._response_approval_lock:
            self._pending_response_approvals[approval_id] = alert
        self._publish_ui_event(
            "response_approval_required",
            f"Approval required before containment: {alert.summary}",
            "pending",
            approval_id=approval_id,
            request_id=approval_id,
            tool="cyberos_containment",
            arguments={
                "alert_id": alert.event_id,
                "summary": alert.summary,
                "proposed_actions": list(alert.recommended_actions),
            },
            alert=alert.to_dict(),
            proposed_actions=list(alert.recommended_actions),
            disruptive_actions_require_human_approval=True,
        )
        return approval_id

    def has_pending_response_approval(self, approval_id: str) -> bool:
        """Return whether an approval ID belongs to an active sensor response."""
        if not approval_id:
            return False
        with self._response_approval_lock:
            return approval_id in self._pending_response_approvals

    def get_pending_response_approvals(self) -> List[Dict[str, Any]]:
        """Return the redacted approval context needed by the local UI."""
        with self._response_approval_lock:
            return [
                {
                    "approval_id": approval_id,
                    "alert_id": alert.event_id,
                    "summary": alert.summary,
                    "severity": alert.severity,
                    "proposed_actions": list(alert.recommended_actions),
                }
                for approval_id, alert in self._pending_response_approvals.items()
            ]

    def resolve_response_approval(self, approval_id: str, approved: bool, approved_by: str = "") -> List[str]:
        """Resolve a human approval and execute only the explicitly approved response."""
        with self._response_approval_lock:
            alert = self._pending_response_approvals.pop(approval_id, None)
        if alert is None:
            return []
        requested_decision = bool(approved and approved_by.strip())
        decision_recorded = self.approval_engine.resolve_approval_request(approval_id, requested_decision)
        if decision_recorded:
            resolved_decision, _ = self.approval_engine.wait_for_human_approval(approval_id, timeout=0)
            decision_recorded = resolved_decision == requested_decision
        if not decision_recorded or not approved or not approved_by.strip():
            self._publish_ui_event(
                "response_approval_resolved",
                "Containment was not approved",
                "denied",
                approval_id=approval_id,
                approved_by=approved_by,
            )
            return []
        with self._response_approval_lock:
            self._approved_response_ids.add(approval_id)
        actions = self._execute_response(alert, approval_id=approval_id)
        alert.actions_taken = actions
        alert.autonomous_action_taken = False
        if actions:
            self.actions_log.append(alert)
        self._publish_ui_event(
            "response_approval_resolved",
            "Approved containment actions completed" if actions else "Approval recorded; no supported containment target was found",
            "completed" if actions else "no_action",
            approval_id=approval_id,
            approved_by=approved_by,
            actions=actions,
        )
        return actions

    def _execute_response(self, alert: ThreatAlert, *, approval_id: str = "") -> List[str]:
        """Execute response actions only after a human explicitly approves."""
        with self._response_approval_lock:
            approved = bool(approval_id and approval_id in self._approved_response_ids)
            if approved:
                self._approved_response_ids.discard(approval_id)
        if not approved:
            self._request_response_approval(alert)
            return []
        actions = []
        
        # Block IP if network-related
        if "ip" in alert.summary.lower() or "source" in alert.summary.lower():
            ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', alert.summary)
            if ip_match:
                ip = ip_match.group(0)
                if ip not in self.blocked_ips:
                    if self._block_ip(ip, approved=True):
                        actions.append(f"Blocked IP: {ip}")
                        self.blocked_ips.add(ip)
        
        # Kill process if process-related
        if "PID" in alert.summary or "process" in alert.summary.lower():
            pid_match = re.search(r'PID[:\s]+(\d+)', alert.summary)
            if pid_match:
                pid = int(pid_match.group(1))
                if pid not in self.terminated_pids:
                    if self._terminate_process(pid, approved=True):
                        actions.append(f"Terminated process PID: {pid}")
                        self.terminated_pids.add(pid)
        
        return actions

    def _block_ip(self, ip: str, *, approved: bool = False) -> bool:
        """Block an IP via Windows Firewall after explicit approval."""
        if not approved:
            return False
        try:
            ipaddress.ip_address(ip)
            rule_name = f"CyberOS_Block_{ip.replace('.', '_')}"
            completed = subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"],
                shell=False,
                capture_output=True,
                timeout=10,
                check=False,
            )
            return completed.returncode == 0
        except Exception as e:
            print(f"[!] Failed to block IP {ip}: {e}")
            return False

    def _terminate_process(self, pid: int, *, approved: bool = False) -> bool:
        """Terminate a process only after explicit approval."""
        if not approved or pid <= 4 or pid == os.getpid():
            return False
        try:
            completed = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)],
                shell=False,
                capture_output=True,
                timeout=10,
                check=False,
            )
            return completed.returncode == 0
        except Exception as e:
            print(f"[!] Failed to terminate PID {pid}: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get current system status."""
        return {
            "running": self.running,
            "threat_score": self.threat_score,
            "total_events": len(self.events),
            "total_alerts": len(self.alerts),
            "blocked_ips": list(self.blocked_ips),
            "blocked_ports": list(self.blocked_ports),
            "terminated_pids": list(self.terminated_pids),
            "quarantined_files": len(self.quarantined_files),
        }
