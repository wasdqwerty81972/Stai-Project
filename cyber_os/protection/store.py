"""Durable SQLite storage for protection events, scan jobs, and quarantine."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Literal, Optional

from .models import DetectionRule, RuleSet, ScanVerdict


DB_SCHEMA_VERSION = 1

CREATE_TABLES_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS detections (
    detection_id TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('allow', 'block')),
    confidence TEXT NOT NULL CHECK(confidence IN ('high', 'medium', 'low')),
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    file_type TEXT,
    size_bytes INTEGER,
    file_path TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    triage_enqueued INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_detections_created ON detections(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_detections_rule ON detections(rule_id, rule_version);

CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    detection_id TEXT NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    action_type TEXT NOT NULL CHECK(action_type IN ('quarantine', 'restore', 'filter_completion')),
    status TEXT NOT NULL CHECK(status IN ('pending', 'completed', 'failed')),
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_actions_detection ON actions(detection_id);

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id TEXT PRIMARY KEY,
    scope TEXT NOT NULL CHECK(scope IN ('quick', 'system')),
    state TEXT NOT NULL CHECK(state IN ('pending', 'running', 'completed', 'cancelled', 'failed')),
    files_scanned INTEGER NOT NULL DEFAULT 0,
    files_total INTEGER NOT NULL DEFAULT 0,
    detections INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_state ON scan_jobs(state);

CREATE TABLE IF NOT EXISTS quarantine_items (
    item_id TEXT PRIMARY KEY,
    original_path TEXT NOT NULL,
    quarantined_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    action_result TEXT NOT NULL CHECK(action_result IN ('moved', 'failed')),
    detection_id TEXT NOT NULL REFERENCES detections(detection_id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    restored_at TEXT,
    restore_result TEXT CHECK(restore_result IN ('restored', 'refused', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_quarantine_detection ON quarantine_items(detection_id);

CREATE TABLE IF NOT EXISTS filter_completions (
    request_id TEXT PRIMARY KEY,
    final_io_status TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


@dataclass(slots=True)
class ProtectionStatus:
    state: Literal["active", "degraded", "unavailable"]
    driver_state: Literal["running", "stopped", "error", "unknown"]
    service_state: Literal["running", "stopped", "error", "unknown"]
    rules_version: str
    last_scan: Optional[str]
    counts: dict[str, int]
    windows_security: dict[str, Any]
    sensor_coverage: dict[str, Any]
    last_error: Optional[str]


@dataclass(slots=True)
class ScanJob:
    job_id: str
    scope: Literal["quick", "system"]
    state: Literal["pending", "running", "completed", "cancelled", "failed"]
    files_scanned: int
    files_total: int
    detections: int
    errors: int
    started_at: str
    completed_at: Optional[str]
    error_message: Optional[str]


@dataclass(slots=True)
class DetectionRecord:
    detection_id: str
    sha256: str
    rule_id: str
    rule_version: str
    action: Literal["allow", "block"]
    confidence: Literal["high", "medium", "low"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    file_type: Optional[str]
    size_bytes: Optional[int]
    file_path: Optional[str]
    created_at: str
    triage_enqueued: bool


@dataclass(slots=True)
class QuarantineItem:
    item_id: str
    original_path: str
    quarantined_path: str
    sha256: str
    rule_id: str
    rule_version: str
    action_result: Literal["moved", "failed"]
    detection_id: str
    created_at: str
    restored_at: Optional[str]
    restore_result: Optional[Literal["restored", "refused", "failed"]]


@dataclass(slots=True)
class WindowsSecurityStatus:
    registered_av_provider: Optional[str]
    defender_mode: Optional[str]
    query_available: bool


class ProtectionStore:
    """Thread-safe SQLite store for protection data."""

    def __init__(self, database_path: Path) -> None:
        self._path = Path(database_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        try:
            conn.executescript(CREATE_TABLES_SQL)
            cursor = conn.execute("SELECT version FROM schema_version")
            row = cursor.fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (DB_SCHEMA_VERSION,))
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            raise

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def record_detection(self, record: DetectionRecord) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO detections
                (detection_id, sha256, rule_id, rule_version, action, confidence, severity,
                 file_type, size_bytes, file_path, created_at, triage_enqueued)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.detection_id,
                    record.sha256,
                    record.rule_id,
                    record.rule_version,
                    record.action,
                    record.confidence,
                    record.severity,
                    record.file_type,
                    record.size_bytes,
                    record.file_path,
                    record.created_at,
                    1 if record.triage_enqueued else 0,
                ),
            )

    def record_action(self, action_id: str, detection_id: str, action_type: str, status: str, details: str = "") -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO actions (action_id, detection_id, action_type, status, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (action_id, detection_id, action_type, status, details),
            )

    def update_action(self, action_id: str, status: str, details: str = "", completed_at: Optional[str] = None) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                UPDATE actions SET status = ?, details = ?, completed_at = ?
                WHERE action_id = ?
                """,
                (status, details, completed_at or datetime.now().isoformat(), action_id),
            )

    def get_status(
        self,
        *,
        driver_state: Literal["running", "stopped", "error", "unknown"] = "unknown",
        service_state: Literal["running", "stopped", "error", "unknown"] = "unknown",
        rules_version: str = "unknown",
        windows_security: Optional[WindowsSecurityStatus] = None,
        sensor_coverage: Optional[dict[str, Any]] = None,
        last_error: Optional[str] = None,
    ) -> ProtectionStatus:
        with self._get_conn() as conn:
            # "Detected" counts every detection (block-verdict or observe); a
            # detection is evidence, not a confirmed outcome.
            cursor = conn.execute("SELECT COUNT(*) FROM detections")
            detected = cursor.fetchone()[0]
            # "Blocked" counts ONLY confirmed denied I/O reported by the driver
            # (a STATUS_ACCESS_DENIED filter completion) -- never a mere block
            # verdict. This upholds the spec invariant that Threats Blocked
            # increases only after a confirmed denied operation, so the count
            # cannot be fabricated from a detection that never denied access.
            cursor = conn.execute(
                "SELECT COUNT(*) FROM filter_completions "
                "WHERE final_io_status = 'STATUS_ACCESS_DENIED'"
            )
            blocked = cursor.fetchone()[0]
            # "Quarantined" counts only verified moves into the quarantine store.
            cursor = conn.execute("SELECT COUNT(*) FROM quarantine_items WHERE action_result = 'moved'")
            quarantined = cursor.fetchone()[0]
            cursor = conn.execute("SELECT MAX(created_at) FROM detections")
            last_scan = cursor.fetchone()[0]

        windows_sec = windows_security or WindowsSecurityStatus(None, None, False)
        sensor_cov = sensor_coverage or {}

        return ProtectionStatus(
            state="active" if driver_state == "running" and service_state == "running" else "degraded",
            driver_state=driver_state,
            service_state=service_state,
            rules_version=rules_version,
            last_scan=last_scan,
            counts={"detected": detected, "blocked": blocked, "quarantined": quarantined},
            windows_security={
                "registered_av_provider": windows_sec.registered_av_provider,
                "defender_mode": windows_sec.defender_mode,
                "query_available": windows_sec.query_available,
            },
            sensor_coverage=sensor_cov,
            last_error=last_error,
        )

    def list_threats(self, limit: int = 100) -> list[DetectionRecord]:
        with self._get_conn() as conn:
            cursor = conn.execute(
                "SELECT * FROM detections ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            return [self._row_to_detection(row) for row in cursor.fetchall()]

    def create_scan_job(self, job_id: str, scope: Literal["quick", "system"]) -> ScanJob:
        job = ScanJob(
            job_id=job_id,
            scope=scope,
            state="pending",
            files_scanned=0,
            files_total=0,
            detections=0,
            errors=0,
            started_at=datetime.now().isoformat(),
            completed_at=None,
            error_message=None,
        )
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs
                (job_id, scope, state, files_scanned, files_total, detections, errors, started_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (job.job_id, job.scope, job.state, job.files_scanned, job.files_total,
                 job.detections, job.errors, job.started_at),
            )
        return job

    def update_scan_job(
        self,
        job_id: str,
        *,
        state: Optional[Literal["pending", "running", "completed", "cancelled", "failed"]] = None,
        files_scanned: Optional[int] = None,
        files_total: Optional[int] = None,
        detections: Optional[int] = None,
        errors: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> bool:
        with self._transaction() as conn:
            updates = []
            params: list[Any] = []
            if state is not None:
                updates.append("state = ?")
                params.append(state)
            if files_scanned is not None:
                updates.append("files_scanned = ?")
                params.append(files_scanned)
            if files_total is not None:
                updates.append("files_total = ?")
                params.append(files_total)
            if detections is not None:
                updates.append("detections = ?")
                params.append(detections)
            if errors is not None:
                updates.append("errors = ?")
                params.append(errors)
            if error_message is not None:
                updates.append("error_message = ?")
                params.append(error_message)
            if state in ("completed", "failed", "cancelled"):
                updates.append("completed_at = ?")
                params.append(datetime.now().isoformat())
            if not updates:
                return False
            params.append(job_id)
            cursor = conn.execute(
                f"UPDATE scan_jobs SET {', '.join(updates)} WHERE job_id = ?", params
            )
            return cursor.rowcount > 0

    def get_scan_job(self, job_id: str) -> Optional[ScanJob]:
        with self._get_conn() as conn:
            cursor = conn.execute("SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return ScanJob(
                job_id=row["job_id"],
                scope=row["scope"],
                state=row["state"],
                files_scanned=row["files_scanned"],
                files_total=row["files_total"],
                detections=row["detections"],
                errors=row["errors"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                error_message=row["error_message"],
            )

    def record_filter_completion(self, request_id: str, final_io_status: str) -> bool:
        with self._transaction() as conn:
            cursor = conn.execute(
                "SELECT 1 FROM filter_completions WHERE request_id = ?", (request_id,)
            )
            if cursor.fetchone():
                return False
            conn.execute(
                "INSERT INTO filter_completions (request_id, final_io_status) VALUES (?, ?)",
                (request_id, final_io_status),
            )
            return final_io_status == "STATUS_ACCESS_DENIED"

    def _row_to_detection(self, row: sqlite3.Row) -> DetectionRecord:
        return DetectionRecord(
            detection_id=row["detection_id"],
            sha256=row["sha256"],
            rule_id=row["rule_id"],
            rule_version=row["rule_version"],
            action=row["action"],
            confidence=row["confidence"],
            severity=row["severity"],
            file_type=row["file_type"],
            size_bytes=row["size_bytes"],
            file_path=row["file_path"],
            created_at=row["created_at"],
            triage_enqueued=bool(row["triage_enqueued"]),
        )