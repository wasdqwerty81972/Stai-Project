#!/usr/bin/env python3
"""
Finding Enricher for STAI 2 Cybersecurity Agent

Adapted from Vigil SOC (github.com/Vigil-SOC/vigil) scripts/enrich_findings.py
Automatically enriches findings with MITRE ATT&CK techniques based on patterns.

Usage:
    python vigil_tools/finding_enricher.py --finding-id f-20260114-001
    python vigil_tools/finding_enricher.py --data-source dns --auto-enrich
    python vigil_tools/finding_enricher.py --bulk-file enrichment.json
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MITRE_PATTERNS = {
    "dns_tunnel": {
        "condition": lambda f: f.get("data_source") == "dns",
        "checks": [
            lambda e: len(e.get("query_name", "")) > 50,
            lambda e: e.get("query_name", "").count(".") > 5,
        ],
        "enrichment": {"mitre_predictions": {"T1071.004": 0.70, "T1048.003": 0.65}, "severity": "high"},
    },
    "beaconing": {
        "condition": lambda f: f.get("entity_context", {}).get("connection_count", 0) > 100,
        "checks": [],
        "enrichment": {"mitre_predictions": {"T1071": 0.75, "T1573": 0.60}, "severity": "medium"},
    },
    "powershell_encoded": {
        "condition": lambda f: "powershell" in f.get("raw_log", "").lower() and "-encodedcommand" in f.get("raw_log", "").lower(),
        "checks": [],
        "enrichment": {"mitre_predictions": {"T1059.001": 0.85, "T1027": 0.70}, "severity": "high"},
    },
    "rdp_unusual": {
        "condition": lambda f: f.get("entity_context", {}).get("dst_port") == 3389,
        "checks": [
            lambda e: not e.get("src_ip", "").startswith("10."),
        ],
        "enrichment": {"mitre_predictions": {"T1021.001": 0.80}, "severity": "medium"},
    },
    "data_exfil": {
        "condition": lambda f: f.get("entity_context", {}).get("bytes_out", 0) > 100_000_000,
        "checks": [],
        "enrichment": {"mitre_predictions": {"T1048": 0.70}, "severity": "medium"},
    },
    "credential_dump": {
        "condition": lambda f: "lsass" in f.get("raw_log", "").lower() or "credential" in f.get("description", "").lower(),
        "checks": [],
        "enrichment": {"mitre_predictions": {"T1003.001": 0.85, "T1558": 0.70}, "severity": "critical"},
    },
    "ransomware": {
        "condition": lambda f: "ransomware" in f.get("description", "").lower() or "encrypt" in f.get("description", "").lower(),
        "checks": [],
        "enrichment": {"mitre_predictions": {"T1486": 0.95, "T1490": 0.85}, "severity": "critical"},
    },
}


def match_patterns(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for pattern_name, pattern in MITRE_PATTERNS.items():
        try:
            if pattern["condition"](finding):
                if not pattern["checks"] or all(check(finding.get("entity_context", {})) for check in pattern["checks"]):
                    return pattern["enrichment"]
        except Exception:
            continue
    return None


def enrich_finding(finding: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
    enrichment = match_patterns(finding)
    if enrichment:
        if dry_run:
            logger.info(f"[DRY RUN] Would enrich {finding.get('finding_id')} with: {enrichment}")
        else:
            finding.setdefault("mitre_predictions", {}).update(enrichment.get("mitre_predictions", {}))
            if "severity" in enrichment:
                finding["severity"] = enrichment["severity"]
            finding["enriched"] = True
            finding["enrichment_source"] = "auto_pattern"
            logger.info(f"Enriched {finding['finding_id']}")
    return finding


def auto_enrich_findings(findings: List[Dict[str, Any]], dry_run: bool = False) -> int:
    unenriched = [f for f in findings if not f.get("mitre_predictions")]
    logger.info(f"Found {len(unenriched)} findings to enrich")
    count = 0
    for finding in unenriched:
        before = finding.get("mitre_predictions", {})
        enrich_finding(finding, dry_run=dry_run)
        after = finding.get("mitre_predictions", {})
        if after != before:
            count += 1
    logger.info(f"Enriched {count} findings")
    return count


def bulk_enrich_from_file(file_path: Path, dry_run: bool = False) -> int:
    if not file_path.exists():
        logger.error(f"File not found: {file_path}")
        return 0
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    findings = data.get("findings", [])
    if not findings:
        logger.error("No findings found in file")
        return 0
    return auto_enrich_findings(findings, dry_run=dry_run)


def main():
    parser = argparse.ArgumentParser(description="Enrich findings with MITRE ATT&CK techniques")
    parser.add_argument("--finding-id", type=str, help="Finding ID to enrich")
    parser.add_argument("--data-source", type=str, help="Filter by data source")
    parser.add_argument("--auto-enrich", action="store_true", help="Auto-enrich unenriched findings")
    parser.add_argument("--bulk-file", type=Path, help="Bulk enrich from JSON file")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done")
    args = parser.parse_args()

    if args.bulk_file:
        count = bulk_enrich_from_file(args.bulk_file, dry_run=args.dry_run)
        print(f"Enriched {count} findings")
    elif args.auto_enrich:
        findings_file = Path(__file__).parent.parent / "data" / "findings.json"
        if findings_file.exists():
            with open(findings_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            count = auto_enrich_findings(data.get("findings", []), dry_run=args.dry_run)
            if not args.dry_run:
                with open(findings_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            print(f"Enriched {count} findings")
        else:
            print("No findings.json found. Run sample_data_generator.py first.")
    else:
        print("Use --auto-enrich or --bulk-file to enrich findings.")


if __name__ == "__main__":
    main()
