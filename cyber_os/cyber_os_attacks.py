"""Inert synthetic attack scenarios for the CyberOS demonstration dashboard.

These scenarios inject simulated detections into the live engine pipeline. They
do not run commands, open network connections, or modify files on the host.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from cyber_os.engine import Severity, ThreatAlert


_SCENARIOS = {
    "bruteforce": {
        "alert_type": "brute_force",
        "technique": "T1110.001",
        "technique_name": "Password Guessing",
        "summary": "Simulated burst of failed logons detected",
        "evidence": ["Synthetic demonstration event: 8 failed logons in 60 seconds"],
        "actions": ["Review the source and target account", "Consider account protection"],
    },
    "powershell": {
        "alert_type": "suspicious_powershell",
        "technique": "T1059.001",
        "technique_name": "PowerShell",
        "summary": "Simulated suspicious PowerShell execution detected",
        "evidence": ["Synthetic demonstration event: encoded PowerShell command pattern"],
        "actions": ["Review the process evidence", "Check for related child processes"],
    },
    "portscan": {
        "alert_type": "port_scan",
        "technique": "T1046",
        "technique_name": "Network Service Scanning",
        "summary": "Simulated rapid connection attempts detected from 203.0.113.42",
        "evidence": ["Synthetic demonstration event: 20 destination ports in 10 seconds"],
        "actions": ["Review related network activity", "Request approval before blocking the source"],
    },
    "ransomware": {
        "alert_type": "ransomware_behavior",
        "technique": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "summary": "Simulated rapid file-change pattern detected",
        "evidence": ["Synthetic demonstration event: burst of file changes; no files were touched"],
        "actions": ["Review the originating process", "Use the local protection service for confirmed file indicators"],
    },
}


def _inject_synthetic_detection(attack_type: str, engine: Any) -> ThreatAlert:
    """Send one inert simulated detection through the engine's normal alert path."""
    if not getattr(engine, "running", False):
        raise RuntimeError("Start CyberOS monitoring before launching a demo scenario")

    scenario = _SCENARIOS[attack_type]
    alert = ThreatAlert(
        timestamp=datetime.now(timezone.utc).isoformat(),
        alert_type=scenario["alert_type"],
        severity=Severity.HIGH.value,
        mitre_technique=scenario["technique"],
        technique_name=scenario["technique_name"],
        summary=scenario["summary"],
        evidence=list(scenario["evidence"]),
        ai_reasoning=(
            "This is a synthetic CyberOS demonstration alert. It exercises alert "
            "display and the approval request path without performing host activity."
        ),
        blast_radius="Simulated only; no host activity was performed.",
        threat_score=8,
        recommended_actions=list(scenario["actions"]),
        event_id=f"DEMO-{attack_type}-{uuid.uuid4().hex}",
    )
    engine._handle_sensor_event(alert)
    return alert


def launch_attack(attack_type: str, engine: Any) -> ThreatAlert:
    """Inject a synthetic detection for one of the demo scenario names."""
    if attack_type not in _SCENARIOS:
        raise ValueError(f"Unknown demo scenario: {attack_type}")
    return _inject_synthetic_detection(attack_type, engine)


def attack_bruteforce(engine: Any) -> ThreatAlert:
    return launch_attack("bruteforce", engine)


def attack_powershell(engine: Any) -> ThreatAlert:
    return launch_attack("powershell", engine)


def attack_portscan(engine: Any) -> ThreatAlert:
    return launch_attack("portscan", engine)


def attack_ransomware(engine: Any) -> ThreatAlert:
    return launch_attack("ransomware", engine)


def restore_test_files() -> None:
    """Retained compatibility no-op; demo scenarios never create test files."""
    return None


if __name__ == "__main__":
    print("CyberOS demo scenarios: bruteforce, powershell, portscan, ransomware")
