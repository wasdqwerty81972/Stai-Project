"""Durable, privacy-minimized warning and AI escalation queue for sensors."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from cyber_os.sensors.windows_sensor_service import SensorEvent


@dataclass
class SensorWarning:
    event_id: str
    sensor_ids: list[int]
    timestamp: str
    severity: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    protection_state: str = "unknown"
    ai_state: str = "pending"
    ai_analysis: str | None = None
    classification: str | None = None
    ai_confidence: float | None = None
    protection_action: str | None = None
    recommended_action: str | None = None


class SensorAnomalyRules:
    """Small, explicit rules for observed Windows sensor events."""

    def __init__(self, failed_logons: int = 5, failed_logon_window: int = 60):
        self.failed_logons = max(2, int(failed_logons))
        self.failed_logon_window = max(1, int(failed_logon_window))
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def evaluate(self, event: SensorEvent) -> SensorWarning | None:
        target = event._protection_target
        if event.event_type == "file_activity" and target:
            suffix = Path(target).suffix.casefold()
            if suffix in {".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js"}:
                return SensorWarning(
                    event_id=event.event_id,
                    sensor_ids=list(event.sensor_ids),
                    timestamp=event.timestamp,
                    severity="MEDIUM",
                    summary=f"A new or modified executable or script was observed ({suffix}).",
                    evidence=[f"file_extension:{suffix}"],
                )
        if event.event_type != "failed_logon":
            return None
        now = time.time()
        source = str(event.details.get("source_ip") or "unknown")
        user_hash = str(event.details.get("target_user_hash") or "unknown")
        bucket = hashlib.sha256(f"{source}|{user_hash}".encode()).hexdigest()[:16]
        with self._lock:
            failures = self._failures[bucket]
            failures.append(now)
            while failures and now - failures[0] > self.failed_logon_window:
                failures.popleft()
            count = len(failures)
        if count < self.failed_logons:
            return None
        return SensorWarning(
            event_id=event.event_id,
            sensor_ids=list(event.sensor_ids),
            timestamp=event.timestamp,
            severity="HIGH",
            summary=f"Repeated failed logons detected ({count} attempts in {self.failed_logon_window} seconds).",
            evidence=[f"source_ip_sha256:{hashlib.sha256(source.encode()).hexdigest()[:16]}", f"account_hash:{user_hash}"],
        )


class SensorWarningStore:
    """SQLite store with unique event IDs and leased escalation claims."""

    def __init__(self, database_path: str):
        self.database_path = database_path
        self._lock = threading.RLock()
        os.makedirs(os.path.dirname(os.path.abspath(database_path)), exist_ok=True)
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sensor_warnings ("
                "event_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, warning_json TEXT NOT NULL, "
                "ai_state TEXT NOT NULL, worker_id TEXT, lease_until REAL, attempts INTEGER NOT NULL DEFAULT 0)"
            )

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.database_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def add(self, warning: SensorWarning) -> bool:
        payload = asdict(warning)
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO sensor_warnings(event_id, created_at, warning_json, ai_state) VALUES(?,?,?,?)",
                (warning.event_id, datetime.now(timezone.utc).isoformat(), json.dumps(payload), warning.ai_state),
            )
            return cursor.rowcount == 1

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT warning_json, ai_state FROM sensor_warnings ORDER BY created_at DESC LIMIT ?",
                (max(0, min(500, int(limit))),),
            ).fetchall()
        output = []
        for row in rows:
            item = json.loads(row["warning_json"])
            item["ai_state"] = row["ai_state"]
            output.append(item)
        return output

    def get(self, event_id: str) -> dict[str, Any] | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT warning_json, ai_state FROM sensor_warnings WHERE event_id=?", (event_id,)
            ).fetchone()
        if row is None:
            return None
        item = json.loads(row["warning_json"])
        item["ai_state"] = row["ai_state"]
        return item

    def update_protection_outcome(self, event_id: str, state: str, action: str | None = None) -> None:
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT warning_json FROM sensor_warnings WHERE event_id=?", (event_id,)).fetchone()
            if row is None:
                return
            warning = json.loads(row["warning_json"])
            warning["protection_state"] = state
            warning["protection_action"] = action
            conn.execute(
                "UPDATE sensor_warnings SET warning_json=? WHERE event_id=?",
                (json.dumps(warning), event_id),
            )

    def claim(self, worker_id: str, limit: int = 20, lease_seconds: float = 60.0) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock, self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT event_id, warning_json FROM sensor_warnings "
                "WHERE ai_state IN ('pending','failed') OR (ai_state='running' AND lease_until < ?) "
                "ORDER BY created_at LIMIT ?",
                (now, max(0, min(100, int(limit)))),
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE sensor_warnings SET ai_state='running', worker_id=?, lease_until=?, attempts=attempts+1 WHERE event_id=?",
                    (worker_id, now + max(1.0, lease_seconds), row["event_id"]),
                )
            conn.commit()
        return [json.loads(row["warning_json"]) for row in rows]

    def complete(self, event_id: str, worker_id: str, result: Mapping[str, Any]) -> bool:
        analysis = str(result.get("analysis") or "")[:4000]
        state = "failed" if result.get("error") else "completed"
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT warning_json, worker_id, ai_state FROM sensor_warnings WHERE event_id=?", (event_id,)).fetchone()
            if row is None or row["worker_id"] != worker_id or row["ai_state"] != "running":
                return False
            warning = json.loads(row["warning_json"])
            warning["ai_analysis"] = analysis or None
            warning["ai_state"] = state
            classification = result.get("classification")
            if isinstance(classification, str):
                warning["classification"] = classification[:32]
            confidence = result.get("confidence")
            if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
                warning["ai_confidence"] = max(0.0, min(1.0, float(confidence)))
            recommended = result.get("recommended_action")
            if isinstance(recommended, str):
                warning["recommended_action"] = recommended[:200]
            action = result.get("protection_action")
            if isinstance(action, str):
                warning["protection_action"] = action[:64]
            conn.execute(
                "UPDATE sensor_warnings SET warning_json=?, ai_state=?, worker_id=NULL, lease_until=NULL WHERE event_id=?",
                (json.dumps(warning), state, event_id),
            )
            return True


class SensorResponseCoordinator:
    """Persist rule-matched warnings before handing them to the AI consumer."""

    def __init__(
        self,
        store: SensorWarningStore,
        rules: SensorAnomalyRules | None = None,
        protection_service: Any | None = None,
    ):
        self.store = store
        self.rules = rules or SensorAnomalyRules()
        self.protection_service = protection_service

    def submit_event(self, event: SensorEvent) -> None:
        verdict = None
        protection_state = "unknown"
        target = event._protection_target
        if event.event_type == "file_activity" and target and self.protection_service is not None:
            try:
                verdict, protection_state = self.protection_service.scan_file_for_sensor(Path(target))
            except Exception:
                protection_state = "failed"
        warning = self.rules.evaluate(event)
        if warning is not None and verdict is not None and verdict.status == "clean" and verdict.sha256:
            warning.evidence.append(f"sha256:{verdict.sha256}")
        if verdict is not None and verdict.status == "detected" and verdict.action == "block":
            warning = SensorWarning(
                event_id=event.event_id,
                sensor_ids=list(event.sensor_ids),
                timestamp=event.timestamp,
                severity="CRITICAL",
                summary="A signed high-confidence antivirus rule matched a file observed by a sensor.",
                evidence=[f"sha256:{verdict.sha256}", f"rule_id:{verdict.rule_id}"],
                protection_state=protection_state,
            )
        if warning is not None:
            warning.protection_state = protection_state
            self.store.add(warning)

    def get_warnings(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.store.list(limit)

    def claim_ai_escalations(self, worker_id: str, limit: int = 20, lease_seconds: float = 60.0) -> list[dict[str, Any]]:
        return self.store.claim(worker_id, limit, lease_seconds)

    def complete_ai_escalation(self, event_id: str, worker_id: str, result: Mapping[str, Any]) -> bool:
        # AI output is investigation evidence only. Any later destructive
        # action must be owned by a separate response-policy controller.
        return self.store.complete(event_id, worker_id, result)
