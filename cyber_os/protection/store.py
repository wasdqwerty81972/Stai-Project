"""Durable SQLite storage for protection events, scan jobs, and quarantine."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Literal, Optional, Sequence

from .models import DetectionRule, RuleSet, ScanVerdict


DB_SCHEMA_VERSION = 6

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
    state TEXT NOT NULL CHECK(state IN ('pending', 'running', 'completed', 'partial', 'cancelled', 'failed')),
    files_scanned INTEGER NOT NULL DEFAULT 0,
    files_total INTEGER NOT NULL DEFAULT 0,
    detections INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    root_snapshot TEXT NOT NULL DEFAULT '[]',
    files_skipped INTEGER NOT NULL DEFAULT 0,
    unknown_verdicts INTEGER NOT NULL DEFAULT 0,
    engine_version TEXT NOT NULL DEFAULT '',
    rules_version TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_state ON scan_jobs(state);

CREATE TABLE IF NOT EXISTS scan_schedule (
    schedule_id INTEGER PRIMARY KEY CHECK(schedule_id = 1),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
    frequency TEXT NOT NULL DEFAULT 'daily' CHECK(frequency IN ('daily', 'weekly')),
    scope TEXT NOT NULL DEFAULT 'quick' CHECK(scope IN ('quick', 'system')),
    local_time TEXT NOT NULL DEFAULT '03:00',
    weekday INTEGER CHECK(weekday BETWEEN 0 AND 6),
    next_run_at TEXT,
    last_run_at TEXT,
    last_job_id TEXT,
    last_result TEXT,
    error_message TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

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

-- Level 2 triage output is isolated from Level 1 detection verdicts.
CREATE TABLE IF NOT EXISTS protection_triage (
    detection_id TEXT PRIMARY KEY REFERENCES detections(detection_id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK(status IN ('queued', 'running', 'completed', 'unavailable', 'failed', 'rejected')),
    summary TEXT,
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS protection_triage_sessions (
    session_id TEXT PRIMARY KEY,
    detection_id TEXT NOT NULL REFERENCES detections(detection_id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_protection_triage_sessions_detection
    ON protection_triage_sessions(detection_id);

CREATE TABLE IF NOT EXISTS protection_triage_messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES protection_triage_sessions(session_id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
    content TEXT NOT NULL CHECK(length(content) <= 4000),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_protection_triage_messages_session
    ON protection_triage_messages(session_id, message_id);

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
    state: Literal["pending", "running", "completed", "partial", "cancelled", "failed"]
    files_scanned: int
    files_total: int
    detections: int
    errors: int
    started_at: str
    completed_at: Optional[str]
    error_message: Optional[str]
    root_snapshot: list[str] = field(default_factory=list)
    files_skipped: int = 0
    unknown_verdicts: int = 0
    engine_version: str = ""
    rules_version: str = ""
    duration_ms: Optional[int] = None


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
class TriageRecord:
    detection_id: str
    status: Literal["queued", "running", "completed", "unavailable", "failed", "rejected"]
    summary: Optional[str]
    error: Optional[str]
    created_at: str
    updated_at: str


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
            columns = {row[1] for row in conn.execute("PRAGMA table_info(scan_jobs)")}
            migrations = {
                "root_snapshot": "TEXT NOT NULL DEFAULT '[]'",
                "files_skipped": "INTEGER NOT NULL DEFAULT 0",
                "unknown_verdicts": "INTEGER NOT NULL DEFAULT 0",
                "engine_version": "TEXT NOT NULL DEFAULT ''",
                "rules_version": "TEXT NOT NULL DEFAULT ''",
                "duration_ms": "INTEGER",
            }
            for name, declaration in migrations.items():
                if name not in columns:
                    conn.execute(f"ALTER TABLE scan_jobs ADD COLUMN {name} {declaration}")
            cursor = conn.execute("SELECT version FROM schema_version")
            row = cursor.fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (DB_SCHEMA_VERSION,))
            elif row[0] < DB_SCHEMA_VERSION:
                # The table rebuild and version bump must be one atomic change.
                # A crash midway must leave the v5 table and version intact so
                # the migration can be retried safely on the next startup.
                conn.execute("BEGIN IMMEDIATE")
                self._migrate_scan_jobs_partial_state(conn)
                conn.execute("DELETE FROM schema_version")
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (DB_SCHEMA_VERSION,))
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            raise

    @staticmethod
    def _migrate_scan_jobs_partial_state(conn: sqlite3.Connection) -> None:
        """Rebuild the scan table to allow truthful partial terminal outcomes."""
        conn.execute("DROP INDEX IF EXISTS idx_scan_jobs_state")
        conn.execute(
            """
            CREATE TABLE scan_jobs_v6 (
                job_id TEXT PRIMARY KEY,
                scope TEXT NOT NULL CHECK(scope IN ('quick', 'system')),
                state TEXT NOT NULL CHECK(state IN ('pending', 'running', 'completed', 'partial', 'cancelled', 'failed')),
                files_scanned INTEGER NOT NULL DEFAULT 0,
                files_total INTEGER NOT NULL DEFAULT 0,
                detections INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0,
                root_snapshot TEXT NOT NULL DEFAULT '[]',
                files_skipped INTEGER NOT NULL DEFAULT 0,
                unknown_verdicts INTEGER NOT NULL DEFAULT 0,
                engine_version TEXT NOT NULL DEFAULT '',
                rules_version TEXT NOT NULL DEFAULT '',
                duration_ms INTEGER,
                started_at TEXT NOT NULL DEFAULT (datetime('now')),
                completed_at TEXT,
                error_message TEXT
            )
            """
        )
        conn.execute(
            """INSERT INTO scan_jobs_v6 (
                    job_id, scope, state, files_scanned, files_total, detections, errors,
                    root_snapshot, files_skipped, unknown_verdicts, engine_version,
                    rules_version, duration_ms, started_at, completed_at, error_message
                )
                SELECT job_id, scope,
                    CASE WHEN state = 'completed'
                        AND (errors > 0 OR files_skipped > 0 OR unknown_verdicts > 0)
                        THEN 'partial' ELSE state END,
                    files_scanned, files_total, detections, errors, root_snapshot,
                    files_skipped, unknown_verdicts, engine_version, rules_version,
                    duration_ms, started_at, completed_at, error_message
                FROM scan_jobs"""
        )
        conn.execute("DROP TABLE scan_jobs")
        conn.execute("ALTER TABLE scan_jobs_v6 RENAME TO scan_jobs")
        conn.execute("CREATE INDEX idx_scan_jobs_state ON scan_jobs(state)")

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

    def get_detection(self, detection_id: str) -> Optional[DetectionRecord]:
        """Read a Level 1 detection without allowing triage to mutate it."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM detections WHERE detection_id = ?", (detection_id,)
            ).fetchone()
            return self._row_to_detection(row) if row else None

    def get_triage_source(self, detection_id: str) -> Optional[dict[str, Any]]:
        """Select only the narrow fields eligible for a triage context."""
        with self._get_conn() as conn:
            row = conn.execute(
                """
                SELECT rule_id, rule_version, action, confidence, severity, file_type, size_bytes
                FROM detections WHERE detection_id = ?
                """,
                (detection_id,),
            ).fetchone()
            return dict(row) if row else None

    def create_triage(
        self,
        detection_id: str,
        *,
        status: Literal["queued", "unavailable", "rejected"],
        error: Optional[str] = None,
    ) -> tuple[TriageRecord, bool]:
        """Create at most one triage record for a detection; never touch verdicts."""
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO protection_triage (detection_id, status, error)
                VALUES (?, ?, ?)
                """,
                (detection_id, status, error),
            )
            row = conn.execute(
                "SELECT * FROM protection_triage WHERE detection_id = ?", (detection_id,)
            ).fetchone()
            if row is None:
                raise LookupError("detection not found")
            return self._row_to_triage(row), cursor.rowcount == 1

    def get_triage(self, detection_id: str) -> Optional[TriageRecord]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM protection_triage WHERE detection_id = ?", (detection_id,)
            ).fetchone()
            return self._row_to_triage(row) if row else None

    def count_triage_jobs(self) -> int:
        with self._get_conn() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM protection_triage").fetchone()[0])

    def update_triage(
        self,
        detection_id: str,
        *,
        status: Literal["queued", "running", "completed", "unavailable", "failed", "rejected"],
        summary: Optional[str] = None,
        error: Optional[str] = None,
    ) -> bool:
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                UPDATE protection_triage
                SET status = ?, summary = ?, error = ?, updated_at = datetime('now')
                WHERE detection_id = ?
                """,
                (status, summary, error, detection_id),
            )
            return cursor.rowcount > 0

    def fail_pending_triage(self, error: str) -> int:
        """Mark queued or running analyses retryable after service shutdown."""
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                UPDATE protection_triage
                SET status = 'failed', summary = NULL, error = ?, updated_at = datetime('now')
                WHERE status IN ('queued', 'running')
                """,
                (error[:256],),
            )
            return cursor.rowcount

    def retry_triage(self, detection_id: str) -> bool:
        """Atomically move one retryable terminal record back to queued."""
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                UPDATE protection_triage
                SET status = 'queued', summary = NULL, error = NULL, updated_at = datetime('now')
                WHERE detection_id = ? AND status IN ('unavailable', 'rejected', 'failed')
                """,
                (detection_id,),
            )
            return cursor.rowcount == 1

    def defer_triage_retry(
        self,
        detection_id: str,
        *,
        status: Literal["unavailable", "rejected"],
        error: str,
    ) -> bool:
        """Update only a terminal retryable record, safe against concurrent work."""
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                UPDATE protection_triage
                SET status = ?, summary = NULL, error = ?, updated_at = datetime('now')
                WHERE detection_id = ? AND status IN ('unavailable', 'rejected', 'failed')
                """,
                (status, error, detection_id),
            )
            return cursor.rowcount == 1

    def create_triage_session(self, session_id: str, detection_id: str) -> bool:
        """Create a session and bind it permanently to one detection."""
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO protection_triage_sessions (session_id, detection_id)
                VALUES (?, ?)
                """,
                (session_id, detection_id),
            )
            return cursor.rowcount == 1

    def get_triage_session_detection(self, session_id: str) -> Optional[str]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT detection_id FROM protection_triage_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            return str(row[0]) if row else None

    def record_triage_message(self, session_id: str, role: Literal["user", "assistant"], content: str) -> None:
        if role not in ("user", "assistant"):
            raise ValueError("invalid triage message role")
        if not isinstance(content, str) or len(content) > 4000:
            raise ValueError("triage message exceeds the size limit")
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO protection_triage_messages (session_id, role, content)
                VALUES (?, ?, ?)
                """,
                (session_id, role, content),
            )

    def list_triage_messages(self, session_id: str, limit: int = 40) -> list[dict[str, str]]:
        bounded_limit = max(1, min(int(limit), 100))
        with self._get_conn() as conn:
            rows = conn.execute(
                """
                SELECT role, content FROM protection_triage_messages
                WHERE session_id = ? ORDER BY message_id DESC LIMIT ?
                """,
                (session_id, bounded_limit),
            ).fetchall()
            return [dict(row) for row in reversed(rows)]

    def create_scan_job(
        self,
        job_id: str,
        scope: Literal["quick", "system"],
        *,
        root_snapshot: Sequence[str] = (),
        engine_version: str = "",
        rules_version: str = "",
    ) -> ScanJob:
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
            root_snapshot=[str(root) for root in root_snapshot],
            engine_version=engine_version,
            rules_version=rules_version,
        )
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs
                (job_id, scope, state, files_scanned, files_total, detections, errors, started_at,
                 root_snapshot, engine_version, rules_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (job.job_id, job.scope, job.state, job.files_scanned, job.files_total,
                 job.detections, job.errors, job.started_at,
                 json.dumps(job.root_snapshot, ensure_ascii=False, separators=(",", ":")),
                 job.engine_version, job.rules_version),
            )
        return job

    def recover_interrupted_scans(self) -> int:
        """Mark nonterminal jobs left by a prior service process as failed."""
        completed_at = datetime.now().isoformat()
        message = "Scan was interrupted when the protection service stopped."
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                UPDATE scan_jobs
                SET state = 'failed', completed_at = ?, error_message = ?
                WHERE state IN ('pending', 'running')
                """,
                (completed_at, message),
            )
            return cursor.rowcount

    def update_scan_job(
        self,
        job_id: str,
        *,
        state: Optional[Literal["pending", "running", "completed", "partial", "cancelled", "failed"]] = None,
        files_scanned: Optional[int] = None,
        files_total: Optional[int] = None,
        detections: Optional[int] = None,
        errors: Optional[int] = None,
        files_skipped: Optional[int] = None,
        unknown_verdicts: Optional[int] = None,
        duration_ms: Optional[int] = None,
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
            if files_skipped is not None:
                updates.append("files_skipped = ?")
                params.append(files_skipped)
            if unknown_verdicts is not None:
                updates.append("unknown_verdicts = ?")
                params.append(unknown_verdicts)
            if duration_ms is not None:
                updates.append("duration_ms = ?")
                params.append(duration_ms)
            if error_message is not None:
                updates.append("error_message = ?")
                params.append(error_message)
            if state in ("completed", "partial", "failed", "cancelled"):
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
                root_snapshot=json.loads(row["root_snapshot"] or "[]"),
                files_skipped=row["files_skipped"],
                unknown_verdicts=row["unknown_verdicts"],
                engine_version=row["engine_version"],
                rules_version=row["rules_version"],
                duration_ms=row["duration_ms"],
            )

    def get_scan_schedule(self) -> dict[str, Any]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM scan_schedule WHERE schedule_id = 1").fetchone()
        if row is None:
            return {
                "enabled": False,
                "frequency": "daily",
                "scope": "quick",
                "local_time": "03:00",
                "weekday": None,
                "next_run_at": None,
                "last_run_at": None,
                "last_job_id": None,
                "last_result": None,
                "error_message": None,
                "updated_at": None,
            }
        schedule = dict(row)
        schedule["enabled"] = bool(schedule["enabled"])
        return schedule

    def save_scan_schedule(
        self,
        *,
        enabled: bool,
        frequency: str,
        scope: str,
        local_time: str,
        weekday: int | None,
        next_run_at: str | None,
    ) -> dict[str, Any]:
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO scan_schedule
                (schedule_id, enabled, frequency, scope, local_time, weekday, next_run_at,
                 last_run_at, last_job_id, last_result, error_message, updated_at)
                VALUES (1, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, datetime('now'))
                ON CONFLICT(schedule_id) DO UPDATE SET
                    enabled = excluded.enabled,
                    frequency = excluded.frequency,
                    scope = excluded.scope,
                    local_time = excluded.local_time,
                    weekday = excluded.weekday,
                    next_run_at = excluded.next_run_at,
                    error_message = NULL,
                    updated_at = datetime('now')
                """,
                (int(enabled), frequency, scope, local_time, weekday, next_run_at),
            )
        return self.get_scan_schedule()

    def update_scan_schedule_run(
        self,
        *,
        next_run_at: str | None,
        last_run_at: str | None = None,
        last_job_id: str | None = None,
        last_result: str | None = None,
        error_message: str | None = None,
    ) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                UPDATE scan_schedule SET next_run_at = ?, last_run_at = ?, last_job_id = ?,
                    last_result = ?, error_message = ?, updated_at = datetime('now')
                WHERE schedule_id = 1
                """,
                (next_run_at, last_run_at, last_job_id, last_result, error_message),
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

    @staticmethod
    def _row_to_triage(row: sqlite3.Row) -> TriageRecord:
        return TriageRecord(
            detection_id=row["detection_id"],
            status=row["status"],
            summary=row["summary"],
            error=row["error"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
