"""
CyberOS Core - MITRE ATT&CK Engine
Maps detections to MITRE techniques and builds attack chains
"""

import json
import os
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

# MITRE ATT&CK Enterprise Matrix (simplified)
MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact"
]

MITRE_TECHNIQUES = {
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell to execute commands.",
        "detection_signals": ["powershell.exe", "powershell", "pwsh", "Invoke-Expression", "IEX"],
        "platforms": ["Windows", "macOS", "Linux"],
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "description": "Adversaries may abuse cmd.exe for execution.",
        "detection_signals": ["cmd.exe", "cmd /c", "cmd /k"],
        "platforms": ["Windows"],
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversaries may use web protocols for C2.",
        "detection_signals": ["http://", "https://", "curl", "wget", "Invoke-WebRequest"],
        "platforms": ["Windows", "macOS", "Linux"],
    },
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may scan for services on accessible hosts.",
        "detection_signals": ["nmap", "masscan", "port scan", "socket scan"],
        "platforms": ["Windows", "macOS", "Linux"],
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt brute force logins.",
        "detection_signals": ["failed logon", "brute force", "authentication failure"],
        "platforms": ["Windows", "macOS", "Linux"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems.",
        "detection_signals": ["ransomware", "encrypted", ".locked", ".enc", ".crypt"],
        "platforms": ["Windows", "macOS", "Linux"],
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "description": "Adversaries may add programs to the Registry run keys.",
        "detection_signals": ["run key", "startup", "RunOnce", "CurrentVersion\\Run"],
        "platforms": ["Windows"],
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "Execution",
        "description": "Adversaries may abuse scheduled tasks.",
        "detection_signals": ["schtasks", "cron", "at.exe", "task scheduler"],
        "platforms": ["Windows", "macOS", "Linux"],
    },
    "T1204.002": {
        "name": "Malicious File",
        "tactic": "Execution",
        "description": "User execution of malicious file.",
        "detection_signals": ["executable", "payload", "dropper", "loader"],
        "platforms": ["Windows", "macOS", "Linux"],
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with malicious attachments.",
        "detection_signals": ["attachment", "phishing", "macro", "email"],
        "platforms": ["Windows", "macOS", "Linux"],
    },
}

MITRE_SOFTWARE = {
    "S0001": {"name": "Mimikatz", "techniques": ["T1003.001"], "type": "Credential Dumper"},
    "S0002": {"name": "PsExec", "techniques": ["T1569.002"], "type": "Remote Service"},
    "S0003": {"name": "PowerShell Empire", "techniques": ["T1059.001"], "type": "Framework"},
    "S0004": {"name": "Cobalt Strike", "techniques": ["T1059.001", "T1071.001"], "type": "Framework"},
    "S0005": {"name": "Metasploit", "techniques": ["T1059.001", "T1071.001"], "type": "Framework"},
}


@dataclass
class AttackTechnique:
    technique_id: str
    name: str
    tactic: str
    confidence: float
    evidence: List[str]
    description: str

    def to_dict(self):
        return {
            'technique_id': self.technique_id,
            'name': self.name,
            'tactic': self.tactic,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'description': self.description,
        }


@dataclass
class AttackChain:
    chain_id: str
    tactics: List[str]
    techniques: List[AttackTechnique]
    evidence: List[str]
    risk_score: float
    confidence: float
    created_at: str

    def to_dict(self):
        return {
            'chain_id': self.chain_id,
            'tactics': self.tactics,
            'techniques': [t.to_dict() for t in self.techniques],
            'evidence': self.evidence,
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'created_at': self.created_at,
        }


class MitreEngine:
    """Maps events and findings to MITRE ATT&CK techniques."""

    def __init__(self):
        self.techniques = MITRE_TECHNIQUES
        self.software = MITRE_SOFTWARE
        self.attack_chains: Dict[str, AttackChain] = {}

    def map_event(self, event: Any) -> List[AttackTechnique]:
        """Map a security event to MITRE techniques."""
        matched_techniques = []

        # Extract event properties
        if hasattr(event, 'to_dict'):
            event_dict = event.to_dict()
        else:
            event_dict = event

        # Combine all text fields for matching
        search_text = " ".join([
            str(event_dict.get('process', '')).lower(),
            str(event_dict.get('command_line', '')).lower(),
            str(event_dict.get('category', '')).lower(),
            " ".join(str(e).lower() for e in event_dict.get('evidence', [])),
        ])

        for technique_id, technique_data in self.techniques.items():
            confidence = 0.0
            matched_signals = []

            for signal in technique_data.get('detection_signals', []):
                if signal.lower() in search_text:
                    confidence += 0.3
                    matched_signals.append(signal)

            if confidence > 0 and matched_signals:
                confidence = min(confidence, 1.0)
                matched_techniques.append(AttackTechnique(
                    technique_id=technique_id,
                    name=technique_data['name'],
                    tactic=technique_data['tactic'],
                    confidence=confidence,
                    evidence=matched_signals,
                    description=technique_data['description'],
                ))

        return matched_techniques

    def map_finding(self, finding: Any) -> List[AttackTechnique]:
        """Map a finding to MITRE techniques."""
        techniques = []

        if hasattr(finding, 'mitre_technique') and finding.mitre_technique:
            technique_id = finding.mitre_technique
            if technique_id in self.techniques:
                technique_data = self.techniques[technique_id]
                techniques.append(AttackTechnique(
                    technique_id=technique_id,
                    name=technique_data['name'],
                    tactic=technique_data['tactic'],
                    confidence=0.85,
                    evidence=[f"Mapped from finding {getattr(finding, 'finding_id', 'unknown')}"],
                    description=technique_data['description'],
                ))

        # Also try mapping through evidence
        if hasattr(finding, 'evidence'):
            search_text = " ".join(str(e).lower() for e in finding.evidence)
            for technique_id, technique_data in self.techniques.items():
                for signal in technique_data.get('detection_signals', []):
                    if signal.lower() in search_text:
                        if not any(t.technique_id == technique_id for t in techniques):
                            techniques.append(AttackTechnique(
                                technique_id=technique_id,
                                name=technique_data['name'],
                                tactic=technique_data['tactic'],
                                confidence=0.6,
                                evidence=[signal],
                                description=technique_data['description'],
                            ))

        return techniques

    def build_attack_chain(self, incident_id: str, techniques: List[AttackTechnique],
                           evidence: List[str]) -> AttackChain:
        """Build a visual attack chain from techniques."""
        chain_id = f"CHAIN-{int(time.time() * 1000) % 100000:05d}-{hash(incident_id) % 10000:04d}"

        # Order techniques by tactic progression
        tactic_order = {tactic: i for i, tactic in enumerate(MITRE_TACTICS)}
        sorted_techniques = sorted(techniques, key=lambda t: tactic_order.get(t.tactic, 999))

        # Get unique tactics in order
        tactics = []
        seen_tactics = set()
        for t in sorted_techniques:
            if t.tactic not in seen_tactics:
                tactics.append(t.tactic)
                seen_tactics.add(t.tactic)

        # Calculate risk score based on technique severity
        risk_score = min(sum(t.confidence * 20 for t in sorted_techniques) / len(sorted_techniques) * 10, 100) if sorted_techniques else 0
        confidence = sum(t.confidence for t in sorted_techniques) / len(sorted_techniques) if sorted_techniques else 0

        chain = AttackChain(
            chain_id=chain_id,
            tactics=tactics,
            techniques=sorted_techniques,
            evidence=evidence,
            risk_score=risk_score,
            confidence=confidence,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        )

        self.attack_chains[chain_id] = chain
        return chain

    def get_technique_by_id(self, technique_id: str) -> Optional[Dict]:
        """Get technique details by ID."""
        return self.techniques.get(technique_id)

    def get_techniques_by_tactic(self, tactic: str) -> List[Dict]:
        """Get all techniques for a specific tactic."""
        return [
            {"id": tid, **data}
            for tid, data in self.techniques.items()
            if data.get('tactic') == tactic
        ]

    def get_all_tactics(self) -> List[str]:
        """Get all MITRE tactics."""
        return MITRE_TACTICS

    def render_attack_chain_ascii(self, chain: AttackChain) -> str:
        """Render attack chain as ASCII art."""
        lines = []
        lines.append(f"ATTACK CHAIN: {chain.chain_id}")
        lines.append("=" * 50)
        lines.append(f"Risk Score: {chain.risk_score:.1f}/100 | Confidence: {chain.confidence:.0%}")
        lines.append("")

        for i, technique in enumerate(chain.techniques):
            if i > 0:
                lines.append("    ↓")
            lines.append(f"[{technique.technique_id}] {technique.name}")
            lines.append(f"    Tactic: {technique.tactic}")
            lines.append(f"    Confidence: {technique.confidence:.0%}")

        lines.append("")
        lines.append("EVIDENCE:")
        for evidence in chain.evidence[:5]:
            lines.append(f"  - {evidence}")

        return "\n".join(lines)