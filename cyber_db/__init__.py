"""
cyber_db.py

Lightweight database integration layer for the Cybersecurity Agent.
Wraps cyber_soc_engine's storage models with a JSON-first approach
so the AI can query findings, cases, MITRE mappings, and workflows
without requiring PostgreSQL.

All AI database access routes through key_manager.py for reasoning.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure cyber_soc_engine is importable
_CYBER_ENGINE_DIR = Path(__file__).parent / "cyber_soc_engine"
if str(_CYBER_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(_CYBER_ENGINE_DIR))

# Data directory for JSON fallback
DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
FINDINGS_FILE = DATA_DIR / "findings.json"
CASES_FILE = DATA_DIR / "cases.json"


def _load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default


def _save_json(path: Path, data: Any) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception as e:
        print(f"[!] Failed to save {path}: {e}")


class CyberDB:
    """
    Lightweight database layer for the Cybersecurity Agent.

    Uses JSON files as the primary storage (no PostgreSQL required).
    Provides AI-accessible methods for:
      - Findings CRUD
      - Case management
      - MITRE ATT&CK queries
      - Workflow execution
      - Investigation ledger persistence
    """

    def __init__(self):
        self.findings: List[Dict[str, Any]] = _load_json(FINDINGS_FILE, [])
        self.cases: List[Dict[str, Any]] = _load_json(CASES_FILE, [])

    # --- Findings ---

    def add_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        finding.setdefault("finding_id", f"f-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:8]}")
        finding.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        finding.setdefault("status", "new")
        finding.setdefault("severity", "medium")
        self.findings.append(finding)
        _save_json(FINDINGS_FILE, self.findings)
        return finding

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        for f in self.findings:
            if f.get("finding_id") == finding_id:
                return f
        return None

    def list_findings(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        results = self.findings
        if filters:
            if "severity" in filters:
                results = [f for f in results if f.get("severity") == filters["severity"]]
            if "data_source" in filters:
                results = [f for f in results if f.get("data_source") == filters["data_source"]]
            if "status" in filters:
                results = [f for f in results if f.get("status") == filters["status"]]
            if "days_back" in filters:
                cutoff = datetime.now(timezone.utc) - timedelta(days=filters["days_back"])
                results = [f for f in results if datetime.fromisoformat(f.get("timestamp", "")) > cutoff]
        return sorted(results, key=lambda x: x.get("timestamp", ""), reverse=True)

    def update_finding(self, finding_id: str, **kwargs) -> bool:
        for f in self.findings:
            if f.get("finding_id") == finding_id:
                f.update(kwargs)
                _save_json(FINDINGS_FILE, self.findings)
                return True
        return False

    def delete_finding(self, finding_id: str) -> bool:
        for i, f in enumerate(self.findings):
            if f.get("finding_id") == finding_id:
                self.findings.pop(i)
                _save_json(FINDINGS_FILE, self.findings)
                return True
        return False

    def get_findings_count(self) -> Dict[str, int]:
        counts = {"total": len(self.findings)}
        for f in self.findings:
            sev = f.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    # --- Cases ---

    def create_case(self, case: Dict[str, Any]) -> Dict[str, Any]:
        case.setdefault("case_id", f"case-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:8]}")
        case.setdefault("status", "open")
        case.setdefault("priority", "medium")
        case.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        case.setdefault("timeline", [{"timestamp": case["created_at"], "event": "Case created"}])
        self.cases.append(case)
        _save_json(CASES_FILE, self.cases)
        return case

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        for c in self.cases:
            if c.get("case_id") == case_id:
                return c
        return None

    def list_cases(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        results = self.cases
        if filters:
            if "status" in filters:
                results = [c for c in results if c.get("status") == filters["status"]]
            if "priority" in filters:
                results = [c for c in results if c.get("priority") == filters["priority"]]
        return sorted(results, key=lambda x: x.get("created_at", ""), reverse=True)

    def update_case(self, case_id: str, **kwargs) -> bool:
        for c in self.cases:
            if c.get("case_id") == case_id:
                c.update(kwargs)
                c["updated_at"] = datetime.now(timezone.utc).isoformat()
                _save_json(CASES_FILE, self.cases)
                return True
        return False

    def add_case_event(self, case_id: str, event: str) -> bool:
        for c in self.cases:
            if c.get("case_id") == case_id:
                c.setdefault("timeline", []).append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event": event,
                })
                c["updated_at"] = datetime.now(timezone.utc).isoformat()
                _save_json(CASES_FILE, self.cases)
                return True
        return False

    # --- MITRE ATT&CK ---

    def get_mitre_techniques(self, keywords: Optional[List[str]] = None) -> List[Dict[str, str]]:
        techniques = [
            {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
            {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
            {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Execution"},
            {"id": "T1543", "name": "Create or Modify System Process", "tactic": "Execution"},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Persistence"},
            {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
            {"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion"},
            {"id": "T1070", "name": "Indicator Removal on Host", "tactic": "Defense Evasion"},
            {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
            {"id": "T1558", "name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access"},
            {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
            {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
            {"id": "T1047", "name": "Windows Management Instrumentation", "tactic": "Discovery"},
            {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
            {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
            {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
            {"id": "T1489", "name": "Service Stop", "tactic": "Impact"},
        ]
        if keywords:
            kw_lower = [k.lower() for k in keywords]
            return [t for t in techniques if any(k in t["name"].lower() for k in kw_lower)]
        return techniques

    def map_finding_to_mitre(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        desc = finding.get("description", "").lower()
        text = finding.get("raw_log", "").lower()
        combined = desc + " " + text
        techniques = self.get_mitre_techniques()
        matches = []
        for t in techniques:
            keywords = t["name"].lower().split()
            if any(kw in combined for kw in keywords):
                matches.append(t)
        return matches

    # --- Workflows ---

    def get_workflow(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        from cyber_agent import BUILTIN_WORKFLOWS
        wf = BUILTIN_WORKFLOWS.get(workflow_id)
        if not wf:
            return None
        return {
            "name": wf.name,
            "description": wf.description,
            "phases": [
                {
                    "id": p.id,
                    "name": p.name,
                    "agent": p.agent,
                    "tools": p.tools,
                    "instructions": p.instructions,
                    "approval_required": p.approval_required,
                }
                for p in wf.phases
            ],
        }

    def list_workflows(self) -> List[str]:
        from cyber_agent import BUILTIN_WORKFLOWS
        return list(BUILTIN_WORKFLOWS.keys())

    # --- Agents ---

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        from cyber_agent import BUILTIN_AGENTS
        agent = BUILTIN_AGENTS.get(agent_id)
        if not agent:
            return None
        return {
            "id": agent.id,
            "name": agent.name,
            "icon": agent.icon,
            "color": agent.color,
            "specialization": agent.specialization,
            "tools": agent.recommended_tools,
        }

    def list_agents(self) -> List[Dict[str, Any]]:
        from cyber_agent import BUILTIN_AGENTS
        return [
            {
                "id": a.id,
                "name": a.name,
                "icon": a.icon,
                "color": a.color,
                "specialization": a.specialization,
                "tools": a.recommended_tools,
            }
            for a in BUILTIN_AGENTS.values()
        ]

    # --- Stats ---

    def get_stats(self) -> Dict[str, Any]:
        finding_counts = self.get_findings_count()
        case_counts = {"total": len(self.cases)}
        for c in self.cases:
            status = c.get("status", "unknown")
            case_counts[status] = case_counts.get(status, 0) + 1
        return {
            "findings": finding_counts,
            "cases": case_counts,
            "mitre_techniques": len(self.get_mitre_techniques()),
            "workflows": len(self.list_workflows()),
            "agents": len(self.list_agents()),
        }


# Global singleton
_db: Optional[CyberDB] = None


def get_db() -> CyberDB:
    global _db
    if _db is None:
        _db = CyberDB()
    return _db
