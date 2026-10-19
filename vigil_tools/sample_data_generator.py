#!/usr/bin/env python3
"""
Sample Data Generator for STAI 2 Cybersecurity Agent

Adapted from Vigil SOC (github.com/Vigil-SOC/vigil) scripts/generate_sample_data.py
Generates realistic sample findings and cases for testing and demos.

Usage:
    python vigil_tools/sample_data_generator.py --count 20 --cases 3
    python vigil_tools/sample_data_generator.py --file
    python vigil_tools/sample_data_generator.py --seed ransomware
"""

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional


# MITRE ATT&CK techniques for sample data
MITRE_TECHNIQUES = {
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1078.001": "Default Accounts",
    "T1078.002": "Domain Accounts",
    "T1003.001": "LSASS Memory",
    "T1055.001": "DLL Injection",
    "T1055.012": "Process Hollowing",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1047": "WMI",
    "T1053.005": "Scheduled Task",
    "T1547.001": "Registry Run Keys",
    "T1041": "Exfiltration Over C2 Channel",
    "T1567.002": "Exfiltration to Cloud Storage",
    "T1027": "Obfuscated Files",
    "T1070.004": "File Deletion",
    "T1562.001": "Disable or Modify Tools",
    "T1543.003": "Windows Service",
}

DATA_SOURCES = ["edr", "siem", "dns", "proxy", "firewall", "email", "endpoint", "flow"]
SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_WEIGHTS = [0.15, 0.25, 0.35, 0.25]


def generate_ip() -> str:
    if random.random() < 0.6:
        return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_hostname() -> str:
    prefixes = ["ws", "srv", "dc", "web", "db", "app", "dev", "prod", "soc", "sec"]
    return f"{random.choice(prefixes)}-{random.randint(1, 999):03d}"


def generate_username() -> str:
    names = ["admin", "service", "backup", "john", "jane", "alice", "bob", "sysadmin", "analyst"]
    return f"{random.choice(names)}{random.randint(1, 99)}"


def generate_mitre_predictions(seed: Optional[str] = None) -> Dict[str, float]:
    num = random.randint(1, 4)
    techniques = random.sample(list(MITRE_TECHNIQUES.keys()), min(num, len(MITRE_TECHNIQUES)))
    return {tech: round(random.uniform(0.5, 0.99), 3) for tech in techniques}


def generate_entity_context() -> Dict[str, Any]:
    context: Dict[str, Any] = {}
    if random.random() < 0.8:
        context["src_ips"] = [generate_ip() for _ in range(random.randint(1, 3))]
    if random.random() < 0.6:
        context["dest_ips"] = [generate_ip() for _ in range(random.randint(1, 2))]
    if random.random() < 0.7:
        context["hostnames"] = [generate_hostname() for _ in range(random.randint(1, 2))]
    if random.random() < 0.5:
        context["usernames"] = [generate_username()]
    if random.random() < 0.3:
        context["file_hashes"] = [uuid.uuid4().hex for _ in range(random.randint(1, 2))]
    return context


def generate_finding(days_back: int = 30, seed: Optional[str] = None) -> Dict[str, Any]:
    timestamp = datetime.now(timezone.utc) - timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )
    severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS)[0]
    mitre = generate_mitre_predictions(seed)
    techniques = list(mitre.keys())
    primary = techniques[0] if techniques else "T1070"
    technique_name = MITRE_TECHNIQUES.get(primary, "Suspicious Activity")

    finding: Dict[str, Any] = {
        "finding_id": f"f-{timestamp.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}",
        "timestamp": timestamp.isoformat(),
        "data_source": random.choice(DATA_SOURCES),
        "anomaly_score": round(random.uniform(0.3, 0.99), 3),
        "severity": severity,
        "status": random.choice(["new", "investigating", "resolved"]) if random.random() > 0.3 else "new",
        "mitre_predictions": mitre,
        "entity_context": generate_entity_context(),
        "description": f"Detected {technique_name} ({primary}) activity from {random.choice(DATA_SOURCES)} data source",
    }

    if seed:
        finding["seed"] = seed
    return finding


def generate_case(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    num = min(random.randint(2, 5), len(findings))
    selected = random.sample(findings, num)
    severities = [f["severity"] for f in selected]
    if "critical" in severities:
        priority = "critical"
    elif "high" in severities:
        priority = "high"
    else:
        priority = "medium"

    clusters = [f.get("cluster_id") for f in selected if f.get("cluster_id")]
    cluster = clusters[0] if clusters else "suspicious-activity"

    case: Dict[str, Any] = {
        "case_id": f"case-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}",
        "title": f"Investigation: {cluster.replace('c-', '').replace('-', ' ').title()}",
        "description": f"Case created from {num} correlated findings",
        "finding_ids": [f["finding_id"] for f in selected],
        "status": random.choice(["open", "investigating", "closed"]),
        "priority": priority,
        "assignee": generate_username() + "@company.com" if random.random() < 0.5 else "",
        "tags": ["auto-generated", random.choice(["malware", "lateral-movement", "exfiltration", "phishing"])],
        "notes": [],
        "timeline": [{"timestamp": now.isoformat(), "event": "Case created by sample data generator"}],
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }
    return case


def generate_sample_data(num_findings: int = 20, num_cases: int = 3, seed: Optional[str] = None) -> tuple:
    print(f"Generating {num_findings} sample findings...")
    findings = [generate_finding(seed=seed) for _ in range(num_findings)]
    print(f"Generating {num_cases} sample cases...")
    cases = [generate_case(findings) for _ in range(num_cases)]
    return findings, cases


def save_to_files(findings: List[Dict], cases: List[Dict], output_dir: Path = None) -> tuple:
    if output_dir is None:
        output_dir = Path(__file__).parent.parent / "data"
    output_dir.mkdir(exist_ok=True)

    findings_file = output_dir / "findings.json"
    with open(findings_file, "w", encoding="utf-8") as f:
        json.dump({"findings": findings}, f, indent=2)
    print(f"Saved {len(findings)} findings to {findings_file}")

    cases_file = output_dir / "cases.json"
    with open(cases_file, "w", encoding="utf-8") as f:
        json.dump({"cases": cases}, f, indent=2)
    print(f"Saved {len(cases)} cases to {cases_file}")

    return findings_file, cases_file


def main():
    parser = argparse.ArgumentParser(description="Generate sample SOC data")
    parser.add_argument("--count", type=int, default=20, help="Number of findings")
    parser.add_argument("--cases", type=int, default=3, help="Number of cases")
    parser.add_argument("--seed", type=str, default=None, help="Seed scenario (e.g. ransomware)")
    parser.add_argument("--file", action="store_true", help="Save to JSON files")
    args = parser.parse_args()

    findings, cases = generate_sample_data(args.count, args.cases, args.seed)
    print(json.dumps({"findings": findings[:3], "cases": cases}, indent=2))

    if args.file:
        save_to_files(findings, cases)


if __name__ == "__main__":
    main()
