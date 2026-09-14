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
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum

from cyber_os.correlation_engine import CorrelationEngine
from cyber_os.incident_manager import IncidentManager
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
                "require_approval": False,
            }
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
        """Start all monitoring and detection threads."""
        self.running = True
        
        # Start monitors
        self.event_monitor.start()
        self.network_monitor.start()
        self.process_monitor.start()
        self.file_monitor.start()
        self.powershell_monitor.start()
        
        # Start detection thread
        threading.Thread(target=self._detection_loop, daemon=True).start()
        
        # Start response thread
        threading.Thread(target=self._response_loop, daemon=True).start()
        
        print("[+] CyberOS Engine started. All monitors active.")

    def stop(self):
        """Stop all monitoring."""
        self.running = False
        self.event_monitor.stop()
        self.network_monitor.stop()
        self.process_monitor.stop()
        self.file_monitor.stop()
        self.powershell_monitor.stop()
        print("[+] CyberOS Engine stopped.")

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
            normalized = {
                "event_id": event_id,
                "category": "process" if event_type == EventType.PROCESS_CREATION.value else "network" if event_type == EventType.NETWORK_CONNECTION.value else "file" if event_type == EventType.FILE_MODIFICATION.value else "auth" if event_type == EventType.FAILED_LOGON.value else "security",
                "timestamp": getattr(event, "timestamp", ""),
                "process": details.get("name", ""),
                "pid": details.get("pid", 0),
                "parent_pid": details.get("ppid", 0),
                "command_line": details.get("cmdline", ""),
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
        
        if event_id != 4625:
            return None
        
        # Track failed logons from source IP
        # For demo, we'll use a simplified approach
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.config["thresholds"]["failed_logon_window"])
        
        recent_failures = [
            e for e in self.events
            if (isinstance(e, SecurityEvent) and 
                e.event_type == EventType.FAILED_LOGON.value and
                (now - datetime.fromisoformat(e.timestamp)).total_seconds() < self.config["thresholds"]["failed_logon_window"])
        ]
        
        if len(recent_failures) >= self.config["thresholds"]["failed_logons"]:
            return ThreatAlert(
                timestamp=now.isoformat(),
                alert_type="brute_force",
                severity=Severity.HIGH.value,
                mitre_technique="T1110.001",
                technique_name="Password Spraying / Brute Force",
                summary=f"Brute force detected: {len(recent_failures)} failed logons in {self.config['thresholds']['failed_logon_window']}s",
                evidence=[
                    f"Failed logons: {len(recent_failures)}",
                    f"Time window: {self.config['thresholds']['failed_logon_window']} seconds",
                    f"Event IDs: {[e.details.get('event_id') for e in recent_failures[:5]]}",
                ],
                ai_reasoning=f"System detected {len(recent_failures)} failed logon attempts within {self.config['thresholds']['failed_logon_window']} seconds. This pattern indicates an automated password spraying or brute force attack.",
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
        """Consume alerts, execute autonomous responses."""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=0.1)
                
                if self.config["auto_response"].get("critical_threat") and alert.threat_score >= 8:
                    actions = self._execute_response(alert)
                    alert.actions_taken = actions
                    alert.autonomous_action_taken = True
                    self.actions_log.append(alert)
            except queue.Empty:
                continue

    def _execute_response(self, alert: ThreatAlert) -> List[str]:
        """Execute autonomous response actions."""
        actions = []
        
        # Block IP if network-related
        if "ip" in alert.summary.lower() or "source" in alert.summary.lower():
            ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', alert.summary)
            if ip_match:
                ip = ip_match.group(0)
                if ip not in self.blocked_ips:
                    self._block_ip(ip)
                    actions.append(f"Blocked IP: {ip}")
                    self.blocked_ips.add(ip)
        
        # Kill process if process-related
        if "PID" in alert.summary or "process" in alert.summary.lower():
            pid_match = re.search(r'PID[:\s]+(\d+)', alert.summary)
            if pid_match:
                pid = int(pid_match.group(1))
                if pid not in self.terminated_pids:
                    self._terminate_process(pid)
                    actions.append(f"Terminated process PID: {pid}")
                    self.terminated_pids.add(pid)
        
        return actions

    def _block_ip(self, ip: str):
        """Block IP via Windows Firewall."""
        try:
            rule_name = f"CyberOS_Block_{ip.replace('.', '_')}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
        except Exception as e:
            print(f"[!] Failed to block IP {ip}: {e}")

    def _terminate_process(self, pid: int):
        """Terminate a process by PID."""
        try:
            subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True, timeout=10)
        except Exception as e:
            print(f"[!] Failed to terminate PID {pid}: {e}")

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
