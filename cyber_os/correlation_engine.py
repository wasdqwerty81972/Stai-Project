"""
CyberOS Core - Event Correlation Engine
Correlates multiple security events into unified incidents
"""

import json
import time
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

try:
    from cyber_os.telemetry import SecurityEvent, EventSeverity, EventCategory
except ImportError:
    SecurityEvent = dict
    EventSeverity = type('EventSeverity', (), {'INFO': 'INFO', 'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH', 'CRITICAL': 'CRITICAL'})()
    EventCategory = type('EventCategory', (), {'PROCESS': 'process', 'NETWORK': 'network', 'FILE': 'file', 'AUTH': 'auth', 'PERSISTENCE': 'persistence', 'REGISTRY': 'registry', 'SERVICE': 'service', 'DNS': 'dns', 'SECURITY': 'security'})()


class CorrelationEngine:
    """Correlates related security events into incidents."""

    # Correlation rules - each maps event patterns to incident relationships
    CORRELATION_RULES = {
        'PROCESS_CHAIN': {
            'description': 'Process chain escalation: A→B→C→...',
            'conditions': {
                'event_type': EventCategory.PROCESS.value,
                'minimum_events': 3,
                'time_window': 300,  # seconds
                'parent_chain': True,
            },
            'action': 'PROCESS_CHAIN_CORRELATION',
        },
        'PORT_SCAN_CLUSTER': {
            'description': 'Multiple connections from same source to many ports',
            'conditions': {
                'event_type': EventCategory.NETWORK.value,
                'minimum_events': 5,
                'time_window': 60,
                'remote_ip_condition': True,
            },
            'action': 'PORT_SCAN_CORRELATION',
        },
        'AUTH_BRUTE_FORCE': {
            'description': 'Failed authentication attempts from same user/IP',
            'conditions': {
                'event_type': EventCategory.AUTH.value,
                'minimum_events': 5,
                'time_window': 60,
                'same_identity': True,
            },
            'action': 'AUTH_CORRELATION',
        },
        'RANSOMWARE_TRIAGE': {
            'description': 'Mass file modifications with suspicious extensions',
            'conditions': {
                'event_type': EventCategory.FILE.value,
                'minimum_events': 3,
                'time_window': 60,
                'suspicious_extensions': True,
            },
            'action': 'RANSOMWARE_CORRELATION',
        },
    }

    def __init__(self, event_source: Dict[str, Any] = None):
        # Cache of event_id -> SecurityEvent
        self.event_source = event_source or {}
        # Cache of ip -> list of network events
        self.ip_events: Dict[str, List[Dict]] = {}
        # Process chain tracking
        self.process_chains: Dict[int, List[Dict]] = {}
        self.process_events_by_pid: Dict[int, Dict[str, Any]] = {}
        # Authentication tracking
        self.auth_attempts: Dict[str, List[Dict]] = {}
        # File modification tracking
        self.file_mods: List[Dict] = []

    def add_event(self, event: SecurityEvent) -> List[Dict]:
        """Add an event and return any newly correlated incidents."""
        incidents = []

        # Categorize the event
        raw_category = getattr(event, 'category', None) if hasattr(event, 'category') else event.get('category', '')
        event_type = raw_category.value if hasattr(raw_category, 'value') else str(raw_category)
        event_id = getattr(event, 'event_id', '') if hasattr(event, 'event_id') else str(event.get('event_id', ''))
        timestamp = getattr(event, 'timestamp', '') if hasattr(event, 'timestamp') else str(event.get('timestamp', ''))

        # Store event in source
        if event_id:
            self.event_source[event_id] = {
                'event': event,
                'timestamp': timestamp,
            }

        # Category-specific correlation
        if event_type == EventCategory.PROCESS.value:
            incidents.extend(self._correlate_process_chain(event))
        elif event_type == EventCategory.NETWORK.value:
            incidents.extend(self._correlate_network(event))
        elif event_type == EventCategory.AUTH.value:
            incidents.extend(self._correlate_auth(event))
        elif event_type == EventCategory.FILE.value:
            incidents.extend(self._correlate_file(event))

        return incidents

    def _correlate_process_chain(self, event: SecurityEvent) -> List[Dict]:
        """Correlate process execution chains."""
        incidents = []
        try:
            pid = getattr(event, 'pid', 0) if hasattr(event, 'pid') else event.get('pid', 0)
            parent_pid = getattr(event, 'parent_pid', 0) if hasattr(event, 'parent_pid') else event.get('parent_pid', 0)
            process_name = getattr(event, 'process', '') if hasattr(event, 'process') else event.get('process', '')
            command_line = getattr(event, 'command_line', '') if hasattr(event, 'command_line') else event.get('command_line', '')
            event_timestamp = getattr(event, 'timestamp', '') if hasattr(event, 'timestamp') else event.get('timestamp', '')

            if pid not in self.process_chains:
                self.process_chains[pid] = []

            chain_entry = {
                'event_id': str(event.event_id) if hasattr(event, 'event_id') else str(event.get('event_id', '')),
                'process': process_name,
                'pid': pid,
                'parent_pid': parent_pid,
                'command_line': command_line,
                'timestamp': event_timestamp,
            }
            self.process_events_by_pid[pid] = chain_entry

            chain = []
            current = chain_entry
            visited = set()
            while current and current.get('event_id') not in visited:
                visited.add(current.get('event_id'))
                chain.insert(0, current)
                current = self.process_events_by_pid.get(current.get('parent_pid'))
            self.process_chains[pid] = chain

            # Check if this chain matches suspicious patterns
            if len(chain) >= 2:
                # Check for suspicious parent-child relationships
                suspicious_pairs = [
                    ('winword.exe', 'cmd.exe'),
                    ('excel.exe', 'powershell.exe'),
                    ('outlook.exe', 'cmd.exe'),
                    ('chrome.exe', 'powershell.exe'),
                    ('firefox.exe', 'cmd.exe'),
                ]

                recent = chain[-min(5, len(chain)):]
                for suspicious_parent, suspicious_child in suspicious_pairs:
                    last_proc = recent[-1].get('process', '')
                    second_last_proc = recent[-2].get('process', '')
                    if second_last_proc == suspicious_parent and last_proc == suspicious_child:
                                incident = {
                                    'incident_id': f"CORR-{int(time.time() * 1000) % 100000:05d}-{uuid.uuid4().hex[:8]}",
                                    'title': 'Suspicious Process Chain Detected',
                                    'severity': 'HIGH',
                                    'correlation_type': 'PROCESS_CHAIN',
                                    'related_events': [e.get('event_id', '') for e in recent],
                                    'confidence': 0.87,
                                    'evidence': [
                                        f"Process chain: {' -> '.join([e.get('process', '') for e in recent[-3:]])}",
                                        f"Chain length: {len(recent)}",
                                    ],
                                    'risk_score': 75,
                                    'mitre_technique': 'T1059.001',
                                    'created_at': datetime.now().isoformat(),
                                    'entities': {
                                        'processes': [e.get('process', '') for e in recent if e.get('process')],
                                        'pids': [str(e.get('pid', '')) for e in recent if e.get('pid')],
                                    },
                                }
                                incidents.append(incident)

        except Exception:
            pass

        return incidents

    def _correlate_network(self, event: SecurityEvent) -> List[Dict]:
        """Correlate network events."""
        incidents = []
        try:
            remote_ip = getattr(event, 'remote_ip', '') if hasattr(event, 'remote_ip') else event.get('remote_ip', '')
            network_data = getattr(event, 'network', {}) if hasattr(event, 'network') else event.get('network', {})
            local_port = network_data.get('local_port', '') if network_data else ''
            protocol = network_data.get('protocol', '') if network_data else ''

            if remote_ip:
                if remote_ip not in self.ip_events:
                    self.ip_events[remote_ip] = []
                self.ip_events[remote_ip].append({
                    'event_id': str(event.event_id) if hasattr(event, 'event_id') else str(event.get('event_id', '')),
                    'local_port': local_port,
                    'protocol': protocol,
                    'timestamp': timestamp,
                })

                # Check for port scan clustering
                ip_events = self.ip_events[remote_ip]
                # Keep only recent events within the window
                cutoff = datetime.now().timestamp() - 60
                recent_events = [e for e in ip_events if e.get('timestamp', 0) > cutoff]

                unique_ports = set()
                for e in recent_events:
                    port = e.get('local_port', '')
                    if port:
                        try:
                            unique_ports.add(int(port.split(':')[-1]) if ':' in port else int(port))
                        except ValueError:
                            pass

                if len(unique_ports) >= 5:
                    # Port scan detected
                    incident = {
                        'incident_id': f"CORR-{int(time.time() * 1000) % 100000:05d}-{uuid.uuid4().hex[:8]}",
                        'title': 'Port Scan Correlation Detected',
                        'severity': 'HIGH',
                        'correlation_type': 'PORT_SCAN_CLUSTER',
                        'related_events': [e.get('event_id', '') for e in recent_events[-20:]],
                        'confidence': 0.82,
                        'evidence': [
                            f"Connection attempt from {remote_ip}",
                            f"Unique ports accessed: {len(unique_ports)} in 60s",
                        ],
                        'risk_score': 78,
                        'mitre_technique': 'T1046',
                        'created_at': datetime.now().isoformat(),
                    }
                    incidents.append(incident)

                    # Clear after correlation to avoid duplicate firing
                    self.ip_events[remote_ip] = []

        except Exception:
            pass

        return incidents

    def _correlate_auth(self, event: SecurityEvent) -> List[Dict]:
        """Correlate authentication events."""
        incidents = []
        try:
            # Track failed logons by user or source IP
            user = getattr(event, 'user', '') if hasattr(event, 'user') else ''
            if not user:
                user = getattr(event, 'source', '') if hasattr(event, 'source') else ''

            if user:
                if user not in self.auth_attempts:
                    self.auth_attempts[user] = []
                self.auth_attempts[user].append({
                    'event_id': str(event.event_id) if hasattr(event, 'event_id') else str(event.get('event_id', '')),
                    'timestamp': str(event.timestamp) if hasattr(event, 'timestamp') else str(event.get('timestamp', '')),
                })

                # Keep only recent attempts
                cutoff = datetime.now().timestamp() - 60
                recent_attempts = [
                    e for e in self.auth_attempts[user]
                    if e.get('timestamp', '').replace('.', '').isdigit()
                    and float(e.get('timestamp', 0)) > cutoff
                ]

                if len(recent_attempts) >= 5:
                    # Brute force detected
                    incident = {
                        'incident_id': f"CORR-{int(time.time() * 1000) % 100000:05d}-{uuid.uuid4().hex[:8]}",
                        'title': 'Brute Force Authentication Detected',
                        'severity': 'HIGH',
                        'correlation_type': 'AUTH_BRUTE_FORCE',
                        'related_events': [e.get('event_id', '') for e in recent_attempts[-20:]],
                        'confidence': 0.91,
                        'evidence': [
                            f"Multiple failed logons from {user}",
                            f"Count: {len(recent_attempts)} in 60s",
                        ],
                        'risk_score': 85,
                        'mitre_technique': 'T1110.001',
                        'created_at': datetime.now().isoformat(),
                    }
                    incidents.append(incident)

                    # Reset after correlation
                    self.auth_attempts[user] = []

        except Exception:
            pass

        return incidents

    def _correlate_file(self, event: SecurityEvent) -> List[Dict]:
        """Correlate file events."""
        incidents = []
        try:
            # Track mass file modifications
            filepath = getattr(event, 'file', {}).get('path', '') if hasattr(event, 'file') else event.get('file', {}).get('path', '')
            filename = getattr(event, 'file', {}).get('filename', '') if hasattr(event, 'file') else event.get('file', {}).get('filename', '')

            if filepath:
                self.file_mods.append({
                    'event_id': str(event.event_id) if hasattr(event, 'event_id') else str(event.get('event_id', '')),
                    'filepath': filepath,
                    'filename': filename,
                    'timestamp': str(event.timestamp) if hasattr(event, 'timestamp') else str(event.get('timestamp', '')),
                })

                # Keep only recent modifications
                cutoff = datetime.now().timestamp() - 60
                recent_mods = [
                    e for e in self.file_mods
                    if e.get('timestamp', '').replace('.', '').isdigit()
                    and float(e.get('timestamp', 0)) > cutoff
                ]

                # Check for ransomware indicators
                suspicious_extensions = {'.locked', '.encrypted', '.crypt', '.ransom', '.cryptolocker', '.locky'}
                suspicious_count = sum(1 for e in recent_mods 
                                      if e.get('filename', '').lower().endswith(tuple(suspicious_extensions)))

                if suspicious_count >= 2:
                    incident = {
                        'incident_id': f"CORR-{int(time.time() * 1000) % 100000:05d}-{uuid.uuid4().hex[:8]}",
                        'title': 'Ransomware Triage Detected',
                        'severity': 'CRITICAL',
                        'correlation_type': 'RANSOMWARE_TRIAGE',
                        'related_events': [e.get('event_id', '') for e in recent_mods[-30:]],
                        'confidence': 0.88,
                        'evidence': [
                            f"Mass file modifications: {len(recent_mods)} in 60s",
                            f"Suspicious extensions: {suspicious_count}",
                        ],
                        'risk_score': 92,
                        'mitre_technique': 'T1486',
                        'created_at': datetime.now().isoformat(),
                    }
                    incidents.append(incident)

                    # Reset after correlation
                    self.file_mods = []

        except Exception:
            pass

        return incidents