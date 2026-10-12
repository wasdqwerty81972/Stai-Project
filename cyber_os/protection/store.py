"""Durable SQLite storage for protection events, scan jobs, and quarantine."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, time as datetime_time, timedelta
from pathlib import Path
from typing import Any, Iterator, Literal, Optional

from .models import DetectionRule, RuleSet, ScanProfile, ScanRootSnapshot, ScanSchedule, ScanVerdict


DB_SCHEMA_VERSION = 5
KNOWN_SCAN_FOLDER_IDS = ("desktop", "downloads", "startup")
_WEEKDAY_INDEX = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}

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
    error_message TEXT,
    source TEXT NOT NULL DEFAULT 'interactive' CHECK(source IN ('interactive', 'schedule'))
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_state ON scan_jobs(state);

CREATE TABLE IF NOT EXISTS scan_profiles (
    owner_sid TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 1,
    roots_json TEXT NOT NULL,
    refreshed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_job_roots (
    job_id TEXT NOT NULL REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
    folder_id TEXT NOT NULL,
    path TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'scanning', 'scanned', 'skipped', 'partial', 'covered')),
    error TEXT,
    PRIMARY KEY (job_id, folder_id)
);

CREATE TABLE IF NOT EXISTS scan_schedules (
    owner_sid TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
    cadence TEXT NOT NULL CHECK(cadence IN ('daily', 'weekly')),
    local_time TEXT NOT NULL,
    days_json TEXT NOT NULL DEFAULT '[]',
    last_run_date TEXT,
    last_job_id TEXT,
    last_result TEXT,
    next_run_local TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_schedule_runs (
    run_id TEXT PRIMARY KEY,
    owner_sid TEXT NOT NULL REFERENCES scan_schedules(owner_sid) ON DELETE CASCADE,
    occurrence_date TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('claimed', 'completed', 'failed', 'skipped')),
    job_id TEXT REFERENCES scan_jobs(job_id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (owner_sid, occurrence_date)
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
    state: Literal["pending", "running", "completed", "cancelled", "failed"]
    files_scanned: int
    files_total: int
    detections: int
    errors: int
    started_at: str
    completed_at: Optional[str]
    error_message: Optional[str]
    source: Literal["interactive", "schedule"] = "interactive"


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


def _next_schedule_occurrence(
    cadence: Literal["daily", "weekly"],
    local_time: str,
    days_of_week: tuple[str, ...],
    after: datetime,
) -> str:
    scheduled_time = datetime.strptime(local_time, "%H:%M").time()
    for offset in range(8):
        candidate_date = after.date() + timedelta(days=offset)
        if cadence == "weekly" and candidate_date.weekday() not in {
            _WEEKDAY_INDEX[day] for day in days_of_week
        }:
            continue
        candidate = datetime.combine(candidate_date, scheduled_time)
        if candidate > after:
            return candidate.isoformat(timespec="minutes")
    raise ValueError("unable to compute next scan occurrence")


def _row_to_schedule(row: sqlite3.Row) -> ScanSchedule:
    return ScanSchedule(
        owner_sid=str(row["owner_sid"]),
        enabled=bool(row["enabled"]),
        cadence=row["cadence"],
        local_time=str(row["local_time"]),
        days_of_week=tuple(json.loads(row["days_json"])),
        last_run_date=row["last_run_date"],
        last_job_id=row["last_job_id"],
        last_result=row["last_result"],
        next_run_local=row["next_run_local"],
    )


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
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(scan_jobs)")}
            if "source" not in columns:
                conn.execute(
                    "ALTER TABLE scan_jobs ADD COLUMN source TEXT NOT NULL DEFAULT 'interactive'"
                )
            schedule_columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(scan_schedules)")
            }
            if "next_run_local" not in schedule_columns:
                conn.execute("ALTER TABLE scan_schedules ADD COLUMN next_run_local TEXT")
            root_table = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'scan_job_roots'"
            ).fetchone()
            if root_table is not None and "'partial'" not in str(root_table[0]):
                conn.execute("PRAGMA foreign_keys = OFF")
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """CREATE TABLE scan_job_roots_v5 (
                        job_id TEXT NOT NULL REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
                        folder_id TEXT NOT NULL,
                        path TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending', 'scanning', 'scanned', 'skipped', 'partial', 'covered')),
                        error TEXT,
                        PRIMARY KEY (job_id, folder_id)
                    )"""
                )
                conn.execute(
                    """INSERT INTO scan_job_roots_v5 (job_id, folder_id, path, status, error)
                       SELECT job_id, folder_id, path, status, error FROM scan_job_roots"""
                )
                conn.execute("DROP TABLE scan_job_roots")
                conn.execute("ALTER TABLE scan_job_roots_v5 RENAME TO scan_job_roots")
                conn.commit()
                conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.execute("SELECT version FROM schema_version")
            row = cursor.fetchone()
            if row is None:
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (DB_SCHEMA_VERSION,))
            elif row[0] < DB_SCHEMA_VERSION:
                conn.execute("DELETE FROM schema_version")
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

    def create_scan_job(self, job_id: str, scope: Literal["quick", "system"]) -> ScanJob:
        return self.create_scan_job_with_roots(job_id, scope, ())

    def create_scan_job_with_roots(
        self,
        job_id: str,
        scope: Literal["quick", "system"],
        roots: tuple[tuple[str, str], ...],
        *,
        source: Literal["interactive", "schedule"] = "interactive",
    ) -> ScanJob:
        """Create a scan job and its immutable root snapshot atomically."""
        if scope not in ("quick", "system"):
            raise ValueError("invalid scan scope")
        if source not in ("interactive", "schedule"):
            raise ValueError("invalid scan source")
        normalized = tuple((str(folder_id), str(path)) for folder_id, path in roots)
        if scope == "quick" and normalized:
            if tuple(folder_id for folder_id, _path in normalized) != KNOWN_SCAN_FOLDER_IDS:
                raise ValueError("quick scan roots must contain the three known folders")
            if any(not path or "\x00" in path for _folder_id, path in normalized):
                raise ValueError("scan root path is invalid")
        elif scope == "quick" and source == "schedule":
            raise ValueError("scheduled quick scans require a root snapshot")

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
            source=source,
        )
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs
                (job_id, scope, state, files_scanned, files_total, detections, errors, started_at, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (job.job_id, job.scope, job.state, job.files_scanned, job.files_total,
                 job.detections, job.errors, job.started_at, job.source),
            )
            conn.executemany(
                "INSERT INTO scan_job_roots (job_id, folder_id, path) VALUES (?, ?, ?)",
                ((job_id, folder_id, path) for folder_id, path in normalized),
            )
        return job

    def replace_scan_profile(
        self,
        owner_sid: str,
        roots: tuple[tuple[str, str], ...],
        refreshed_at: str,
    ) -> ScanProfile:
        """Atomically publish all three fixed known-folder roots for one SID."""
        normalized = tuple((str(folder_id), str(path)) for folder_id, path in roots)
        if tuple(folder_id for folder_id, _path in normalized) != KNOWN_SCAN_FOLDER_IDS:
            raise ValueError("scan profile requires the three known folders")
        if not owner_sid or "\x00" in owner_sid:
            raise ValueError("scan profile SID is invalid")
        if any(not path or "\x00" in path for _folder_id, path in normalized):
            raise ValueError("scan profile root path is invalid")
        if not refreshed_at:
            raise ValueError("scan profile refresh timestamp is required")
        profile = ScanProfile(owner_sid, normalized, refreshed_at)
        roots_json = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"))
        with self._transaction() as conn:
            conn.execute(
                """
                INSERT INTO scan_profiles (owner_sid, version, roots_json, refreshed_at)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(owner_sid) DO UPDATE SET
                    version = scan_profiles.version + 1,
                    roots_json = excluded.roots_json,
                    refreshed_at = excluded.refreshed_at
                """,
                (owner_sid, roots_json, refreshed_at),
            )
        return profile

    def get_scan_profile(self, owner_sid: str) -> ScanProfile | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT owner_sid, roots_json, refreshed_at FROM scan_profiles WHERE owner_sid = ?",
                (owner_sid,),
            ).fetchone()
        if row is None:
            return None
        try:
            roots = tuple((str(folder_id), str(path)) for folder_id, path in json.loads(row["roots_json"]))
        except (TypeError, ValueError):
            return None
        if tuple(folder_id for folder_id, _path in roots) != KNOWN_SCAN_FOLDER_IDS:
            return None
        return ScanProfile(str(row["owner_sid"]), roots, str(row["refreshed_at"]))

    def get_scan_job_roots(self, job_id: str) -> tuple[tuple[str, str], ...]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT folder_id, path FROM scan_job_roots WHERE job_id = ? ORDER BY rowid",
                (job_id,),
            ).fetchall()
        return tuple((str(row["folder_id"]), str(row["path"])) for row in rows)

    def list_scan_job_root_status(self, job_id: str) -> tuple[ScanRootSnapshot, ...]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT job_id, folder_id, path FROM scan_job_roots WHERE job_id = ? ORDER BY rowid",
                (job_id,),
            ).fetchall()
        return tuple(
            ScanRootSnapshot(str(row["job_id"]), str(row["folder_id"]), str(row["path"]))
            for row in rows
        )

    def update_scan_job_root(
        self,
        job_id: str,
        folder_id: str,
        status: Literal["pending", "scanning", "scanned", "skipped", "partial", "covered"],
        *,
        error: str | None = None,
    ) -> bool:
        if status not in ("pending", "scanning", "scanned", "skipped", "partial", "covered"):
            raise ValueError("invalid scan root status")
        with self._transaction() as conn:
            cursor = conn.execute(
                "UPDATE scan_job_roots SET status = ?, error = ? WHERE job_id = ? AND folder_id = ?",
                (status, (error or "")[:256] or None, job_id, folder_id),
            )
            return cursor.rowcount == 1

    def get_scan_job_root_coverage(self, job_id: str) -> tuple[dict[str, str | None], ...]:
        """Return folder labels/status without disclosing their stored paths."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT folder_id, status, error FROM scan_job_roots WHERE job_id = ? ORDER BY rowid",
                (job_id,),
            ).fetchall()
        return tuple(
            {"folder_id": str(row["folder_id"]), "status": str(row["status"]), "error": row["error"]}
            for row in rows
        )

    def recover_interrupted_scan_jobs(self) -> tuple[str, ...]:
        """Fail scans left pending or running by a previous service process."""
        message = "service restarted while scan was active"
        with self._transaction() as conn:
            rows = conn.execute(
                "SELECT job_id FROM scan_jobs WHERE state IN ('pending', 'running')"
            ).fetchall()
            job_ids = tuple(str(row["job_id"]) for row in rows)
            if not job_ids:
                return ()
            placeholders = ",".join("?" for _ in job_ids)
            conn.execute(
                f"""UPDATE scan_jobs SET state = 'failed', error_message = ?,
                       completed_at = ? WHERE job_id IN ({placeholders})""",
                (message, datetime.now().isoformat(), *job_ids),
            )
            conn.execute(
                f"""UPDATE scan_job_roots
                       SET status = CASE WHEN status IN ('scanning', 'covered') THEN 'partial' ELSE 'skipped' END,
                           error = ?
                       WHERE job_id IN ({placeholders}) AND status IN ('pending', 'scanning', 'covered')""",
                (message, *job_ids),
            )
            conn.execute(
                f"""UPDATE scan_schedule_runs SET state = 'failed'
                       WHERE state = 'claimed' AND job_id IN ({placeholders})""",
                job_ids,
            )
            conn.execute(
                f"""UPDATE scan_schedules SET last_result = 'failed'
                       WHERE last_job_id IN ({placeholders})""",
                job_ids,
            )
            return job_ids

    def set_scan_schedule(
        self,
        owner_sid: str,
        *,
        enabled: bool,
        cadence: Literal["daily", "weekly"],
        local_time: str,
        days_of_week: tuple[str, ...],
        now_local: datetime | None = None,
    ) -> ScanSchedule:
        if not owner_sid or "\x00" in owner_sid:
            raise ValueError("schedule owner SID is invalid")
        if type(enabled) is not bool or cadence not in ("daily", "weekly"):
            raise ValueError("schedule settings are invalid")
        try:
            parsed_time = datetime.strptime(local_time, "%H:%M").time()
        except (TypeError, ValueError) as exc:
            raise ValueError("schedule time must use HH:MM") from exc
        if parsed_time.strftime("%H:%M") != local_time:
            raise ValueError("schedule time must use HH:MM")
        if any(day not in _WEEKDAY_INDEX for day in days_of_week):
            raise ValueError("schedule weekdays are invalid")
        if len(set(days_of_week)) != len(days_of_week):
            raise ValueError("schedule weekdays must be unique")
        days = tuple(sorted(days_of_week, key=lambda day: _WEEKDAY_INDEX[day]))
        if (cadence == "weekly") != bool(days):
            raise ValueError("weekly schedules require weekdays; daily schedules do not")
        now = now_local or datetime.now()
        if now.tzinfo is not None:
            now = now.astimezone().replace(tzinfo=None)
        if enabled and self.get_scan_profile(owner_sid) is None:
            raise ValueError("a successfully resolved scan profile is required before enabling a schedule")
        next_run = _next_schedule_occurrence(cadence, local_time, days, now) if enabled else None
        with self._transaction() as conn:
            conn.execute(
                """INSERT INTO scan_schedules
                   (owner_sid, version, enabled, cadence, local_time, days_json, next_run_local)
                   VALUES (?, 1, ?, ?, ?, ?, ?)
                   ON CONFLICT(owner_sid) DO UPDATE SET
                     version = scan_schedules.version + 1,
                     enabled = excluded.enabled,
                     cadence = excluded.cadence,
                     local_time = excluded.local_time,
                     days_json = excluded.days_json,
                     next_run_local = excluded.next_run_local,
                     updated_at = datetime('now')""",
                (owner_sid, int(enabled), cadence, local_time, json.dumps(days), next_run),
            )
            row = conn.execute(
                "SELECT * FROM scan_schedules WHERE owner_sid = ?", (owner_sid,)
            ).fetchone()
        return _row_to_schedule(row)

    def get_scan_schedule(self, owner_sid: str) -> ScanSchedule | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM scan_schedules WHERE owner_sid = ?", (owner_sid,)
            ).fetchone()
        return _row_to_schedule(row) if row is not None else None

    def claim_due_scan(
        self,
        owner_sid: str,
        now_local: datetime,
        *,
        scan_active: bool,
    ) -> ScanJob | None:
        """Claim one due occurrence and snapshot its roots in the same transaction."""
        now = now_local.astimezone().replace(tzinfo=None) if now_local.tzinfo else now_local
        with self._transaction() as conn:
            conn.execute("BEGIN IMMEDIATE")
            schedule = conn.execute(
                "SELECT * FROM scan_schedules WHERE owner_sid = ? AND enabled = 1",
                (owner_sid,),
            ).fetchone()
            if schedule is None or not schedule["next_run_local"]:
                return None
            due_at = datetime.fromisoformat(schedule["next_run_local"])
            if due_at > now:
                return None
            occurrence_date = due_at.date().isoformat()
            days = tuple(json.loads(schedule["days_json"]))
            next_run = _next_schedule_occurrence(
                schedule["cadence"], schedule["local_time"], days, now
            )
            if schedule["last_run_date"] == occurrence_date:
                conn.execute(
                    "UPDATE scan_schedules SET next_run_local = ? WHERE owner_sid = ?",
                    (next_run, owner_sid),
                )
                return None

            if scan_active:
                conn.execute(
                    """INSERT INTO scan_schedule_runs
                       (run_id, owner_sid, occurrence_date, state) VALUES (?, ?, ?, 'skipped')""",
                    (str(uuid.uuid4()), owner_sid, occurrence_date),
                )
                conn.execute(
                    """UPDATE scan_schedules SET last_run_date = ?, last_job_id = NULL,
                       last_result = 'skipped', next_run_local = ?, updated_at = datetime('now')
                       WHERE owner_sid = ?""",
                    (occurrence_date, next_run, owner_sid),
                )
                return None

            profile = conn.execute(
                "SELECT roots_json FROM scan_profiles WHERE owner_sid = ?", (owner_sid,)
            ).fetchone()
            try:
                roots = tuple((str(folder_id), str(path)) for folder_id, path in json.loads(profile["roots_json"])) if profile else ()
            except (TypeError, ValueError):
                roots = ()
            if tuple(folder_id for folder_id, _path in roots) != KNOWN_SCAN_FOLDER_IDS:
                conn.execute(
                    """INSERT INTO scan_schedule_runs
                       (run_id, owner_sid, occurrence_date, state) VALUES (?, ?, ?, 'failed')""",
                    (str(uuid.uuid4()), owner_sid, occurrence_date),
                )
                conn.execute(
                    """UPDATE scan_schedules SET last_run_date = ?, last_job_id = NULL,
                       last_result = 'failed', next_run_local = ?, updated_at = datetime('now')
                       WHERE owner_sid = ?""",
                    (occurrence_date, next_run, owner_sid),
                )
                return None

            job_id = str(uuid.uuid4())
            started_at = now.isoformat()
            conn.execute(
                """INSERT INTO scan_jobs
                   (job_id, scope, state, files_scanned, files_total, detections, errors, started_at, source)
                   VALUES (?, 'quick', 'pending', 0, 0, 0, 0, ?, 'schedule')""",
                (job_id, started_at),
            )
            conn.executemany(
                "INSERT INTO scan_job_roots (job_id, folder_id, path) VALUES (?, ?, ?)",
                ((job_id, folder_id, path) for folder_id, path in roots),
            )
            conn.execute(
                """INSERT INTO scan_schedule_runs
                   (run_id, owner_sid, occurrence_date, state, job_id)
                   VALUES (?, ?, ?, 'claimed', ?)""",
                (str(uuid.uuid4()), owner_sid, occurrence_date, job_id),
            )
            conn.execute(
                """UPDATE scan_schedules SET last_run_date = ?, last_job_id = ?,
                   last_result = 'running', next_run_local = ?, updated_at = datetime('now')
                   WHERE owner_sid = ?""",
                (occurrence_date, job_id, next_run, owner_sid),
            )
            return ScanJob(
                job_id=job_id,
                scope="quick",
                state="pending",
                files_scanned=0,
                files_total=0,
                detections=0,
                errors=0,
                started_at=started_at,
                completed_at=None,
                error_message=None,
                source="schedule",
            )

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
            if cursor.rowcount and state in ("completed", "failed", "cancelled"):
                schedule_result = "completed" if state == "completed" else "failed"
                conn.execute(
                    "UPDATE scan_schedule_runs SET state = ? WHERE job_id = ? AND state = 'claimed'",
                    (schedule_result, job_id),
                )
                conn.execute(
                    "UPDATE scan_schedules SET last_result = ? WHERE last_job_id = ?",
                    (state, job_id),
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
                source=row["source"] if "source" in row.keys() else "interactive",
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
