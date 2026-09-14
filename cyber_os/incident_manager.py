"""
CyberOS Core - Incident Management Engine
Manages incident lifecycle from detection to closure
"""

import os
import json
import time
import queue
import uuid
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

try:
    from cyber_os.telemetry import SecurityEvent, EventSeverity, EventCategory
except ImportError:
    SecurityEvent = dict
    EventSeverity = type('EventSeverity', (), {'INFO': 'INFO', 'LOW': 'LOW', 'MEDIUM': 'MEDIUM', 'HIGH': 'HIGH', 'CRITICAL': 'CRITICAL'})()
    EventCategory = type('EventCategory', (), {'PROCESS': 'process', 'NETWORK': 'network', 'FILE': 'file', 'AUTH': 'auth', 'PERSISTENCE': 'persistence', 'REGISTRY': 'registry', 'SERVICE': 'service', 'DNS': 'dns', 'SECURITY': 'security'})()


@dataclass
class Finding:
    finding_id: str
    severity: str
    confidence: float
    event_ids: List[str]
    evidence: List[str]
    detection_reason: str
    related_events: List[Dict]
    related_entities: Dict[str, List[str]]
    mitre_technique: str
    recommended_action: str
    status: str

    def to_dict(self):
        return {
            'finding_id': self.finding_id,
            'severity': self.severity,
            'confidence': self.confidence,
            'event_ids': self.event_ids,
            'evidence': self.evidence,
            'detection_reason': self.detection_reason,
            'related_events': self.related_events,
            'related_entities': self.related_entities,
            'mitre_technique': self.mitre_technique,
            'recommended_action': self.recommended_action,
            'status': self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Finding':
        return cls(**data)


INCIDENT_STATUSES = ['NEW', 'INVESTIGATING', 'CONTAINED', 'REMEDIATING', 'RESOLVED', 'CLOSED']


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str
    status: str
    created_at: str
    updated_at: str
    findings: List[str]
    events: List[str]
    entities: Dict[str, List[str]]
    attack_chain: List[str]
    mitre_techniques: List[str]
    recommended_actions: List[str]
    actions_taken: List[Dict[str, Any]]
    audit_entries: List[str]
    risk_score: float
    confidence: float
    evidence_count: int
    detection_count: int
    forensic_timeline: List[Dict[str, str]]

    def to_dict(self):
        return {
            'incident_id': self.incident_id,
            'title': self.title,
            'severity': self.severity,
            'status': self.status,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'findings': self.findings,
            'events': self.events,
            'entities': self.entities,
            'attack_chain': self.attack_chain,
            'mitre_techniques': self.mitre_techniques,
            'recommended_actions': self.recommended_actions,
            'actions_taken': self.actions_taken,
            'audit_entries': self.audit_entries,
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'evidence_count': self.evidence_count,
            'detection_count': self.detection_count,
            'forensic_timeline': self.forensic_timeline,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'Incident':
        return cls(**data)

    def update_status(self, new_status: str):
        if new_status in INCIDENT_STATUSES:
            self.status = new_status
            self.updated_at = datetime.now().isoformat()

    def add_finding(self, finding_id: str):
        if finding_id not in self.findings:
            self.findings.append(finding_id)

    def add_action(self, action: Dict):
        self.actions_taken.append(action)
        self.updated_at = datetime.now().isoformat()

    def add_evidence(self, event_id: str):
        if event_id not in self.events:
            self.events.append(event_id)

    def build_timeline(self, events: Dict[str, SecurityEvent]):
        timeline = []
        sorted_events = sorted(
            self.events,
            key=lambda event_id: getattr(events.get(event_id), "timestamp", "") if events.get(event_id) else "",
        )
        
        for event_id in sorted_events:
            if event_id in events:
                evt = events[event_id]
                timeline.append({
                    'timestamp': evt.timestamp if hasattr(evt, 'timestamp') else '',
                    'event_id': event_id,
                    'description': f"Event {event_id} detected",
                })
        self.forensic_timeline = timeline


class IncidentManager:
    """Manages incident lifecycle and storage."""

    def __init__(self, storage_path: str = 'cyber_db/incidents.json'):
        self.storage_path = storage_path
        self.incidents: Dict[str, Incident] = {}
        self.findings: Dict[str, Finding] = {}
        self._lock = threading.RLock()
        self._load()

    def _load(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    for inc_id, inc_data in data.get('incidents', {}).items():
                        self.incidents[inc_id] = Incident.from_dict(inc_data)
                    for find_id, find_data in data.get('findings', {}).items():
                        self.findings[find_id] = Finding.from_dict(find_data)
            except Exception:
                pass

    def _save(self):
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, 'w') as f:
            json.dump({
                'incidents': {k: v.to_dict() for k, v in self.incidents.items()},
                'findings': {k: v.to_dict() for k, v in self.findings.items()},
            }, f, indent=2)

    def create_incident(self, title: str, severity: str = 'MEDIUM', 
                        risk_score: float = 0, confidence: float = 0,
                        evidence_count: int = 0, detection_count: int = 0,
                        mitre_techniques: List[str] = None) -> Incident:
        incident_id = f"INCIDENT-{int(time.time() * 1000) % 100000:05d}-{uuid.uuid4().hex[:8]}"
        incident = Incident(
            incident_id=incident_id,
            title=title,
            severity=severity,
            status='NEW',
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            findings=[],
            events=[],
            entities={'processes': [], 'files': [], 'network_ips': [], 'users': [], 'pids': []},
            attack_chain=[],
            mitre_techniques=mitre_techniques or [],
            recommended_actions=[],
            actions_taken=[],
            audit_entries=[],
            risk_score=risk_score,
            confidence=confidence,
            evidence_count=evidence_count,
            detection_count=detection_count,
            forensic_timeline=[],
        )
        with self._lock:
            self.incidents[incident_id] = incident
            self._save()
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def get_all_incidents(self, status_filter: str = None) -> List[Incident]:
        with self._lock:
            if status_filter:
                return [i for i in self.incidents.values() if i.status == status_filter]
            return list(self.incidents.values())

    def update_incident(self, incident_id: str, **kwargs) -> bool:
        with self._lock:
            if incident_id not in self.incidents:
                return False
            incident = self.incidents[incident_id]
            for key, value in kwargs.items():
                if hasattr(incident, key):
                    setattr(incident, key, value)
            incident.updated_at = datetime.now().isoformat()
            self._save()
            return True

    def add_finding_to_incident(self, incident_id: str, finding: Finding) -> bool:
        with self._lock:
            if incident_id not in self.incidents:
                return False
            self.findings[finding.finding_id] = finding
            incident = self.incidents[incident_id]
            incident.add_finding(finding.finding_id)
            for event_id in finding.event_ids:
                incident.add_evidence(event_id)
            for entity_type, entities in finding.related_entities.items():
                for entity in entities:
                    if entity not in incident.entities.get(entity_type, []):
                        incident.entities.setdefault(entity_type, []).append(entity)
            self._save()
            return True

    def create_finding(self, severity: str, confidence: float, 
                       evidence: List[str], detection_reason: str,
                       mitre_technique: str = '',
                       recommended_action: str = '',
                       related_entities: Dict[str, List[str]] = None,
                       related_events: List[Dict] = None) -> Finding:
        finding_id = f"FINDING-{int(time.time() * 1000) % 100000:05d}-{uuid.uuid4().hex[:8]}"
        finding = Finding(
            finding_id=finding_id,
            severity=severity,
            confidence=confidence,
            event_ids=[],
            evidence=evidence,
            detection_reason=detection_reason,
            related_events=related_events or [],
            related_entities=related_entities or {'processes': [], 'files': [], 'network_ips': [], 'users': [], 'pids': []},
            mitre_technique=mitre_technique,
            recommended_action=recommended_action,
            status='OPEN',
        )
        with self._lock:
            self.findings[finding_id] = finding
            self._save()
        return finding

    def ingest_correlated_finding(self, correlation: Dict[str, Any], event_index: Dict[str, Any]) -> Incident:
        """Persist one correlated detection as an idempotent incident and finding."""
        related_events = list(dict.fromkeys(correlation.get("related_events", [])))
        correlation_key = f"{correlation.get('correlation_type', 'unknown')}:{','.join(related_events)}"
        with self._lock:
            for incident in self.incidents.values():
                if correlation_key in incident.audit_entries:
                    return incident

            incident = self.create_incident(
                title=correlation.get("title", "Correlated security detection"),
                severity=correlation.get("severity", "MEDIUM"),
                risk_score=correlation.get("risk_score", 0),
                confidence=correlation.get("confidence", 0),
                evidence_count=len(correlation.get("evidence", [])),
                detection_count=1,
                mitre_techniques=[correlation["mitre_technique"]] if correlation.get("mitre_technique") else [],
            )
            incident.audit_entries.append(correlation_key)
            incident.attack_chain = []
            for event_id in related_events:
                event = event_index.get(event_id)
                process = getattr(event, "process", "") if event else ""
                if not process and event:
                    process = getattr(event, "details", {}).get("name", "")
                if process:
                    incident.attack_chain.append(process)
            for event_id in related_events:
                incident.add_evidence(event_id)
            for entity_type, values in correlation.get("entities", {}).items():
                incident.entities.setdefault(entity_type, [])
                incident.entities[entity_type].extend(value for value in values if value not in incident.entities[entity_type])
            finding = self.create_finding(
                severity=correlation.get("severity", "MEDIUM"),
                confidence=correlation.get("confidence", 0),
                evidence=correlation.get("evidence", []),
                detection_reason=correlation.get("correlation_type", "correlated_detection"),
                mitre_technique=correlation.get("mitre_technique", ""),
                recommended_action="Review and approve containment actions if required.",
                related_entities=correlation.get("entities", {}),
                related_events=[event_index[event_id].to_dict() if hasattr(event_index.get(event_id), "to_dict") else {} for event_id in related_events],
            )
            finding.event_ids = related_events
            self.findings[finding.finding_id] = finding
            incident.add_finding(finding.finding_id)
            incident.build_timeline(event_index)
            self._save()
            return incident

    def delete_incident(self, incident_id: str) -> bool:
        with self._lock:
            if incident_id in self.incidents:
                del self.incidents[incident_id]
                self._save()
                return True
            return False

    def get_statistics(self) -> Dict[str, Any]:
        with self._lock:
            incidents = list(self.incidents.values())
            findings = list(self.findings.values())
            severities = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            statuses = dict.fromkeys(INCIDENT_STATUSES, 0)
            
            for f in findings:
                if f.severity in severities:
                    severities[f.severity] += 1
            
            for i in incidents:
                if i.status in statuses:
                    statuses[i.status] += 1
            
            return {
                'total_incidents': len(incidents),
                'total_findings': len(findings),
                'by_severity': severities,
                'by_status': statuses,
                'open_incidents': statuses.get('NEW', 0) + statuses.get('INVESTIGATING', 0),
                'risk_score_avg': sum(i.risk_score for i in incidents) / len(incidents) if incidents else 0,
            }