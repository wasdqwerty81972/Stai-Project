"""Durable SQLite storage for protection events, scan jobs, and quarantine."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, Literal, Optional, Sequence

from .models import DetectionRule, RuleSet, ScanVerdict, ThreatIntelEvidence


DB_SCHEMA_VERSION = 8
LOGGER = logging.getLogger(__name__)

CREATE_TABLES_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

-- The sha1/md5/threat_family/intel_source/intel_confidence/feed_version
-- columns are schema v7 intel provenance. They are declared in the CREATE so
-- a fresh database has them, and backfilled by
-- _migrate_detection_intel_columns on an existing one. Keep this note OUTSIDE
-- the CREATE body: SQLite stores the statement text verbatim and re-parses it
-- on ALTER TABLE ... DROP COLUMN, where an interior comment makes the rewrite
-- fail with "incomplete input" -- which would break the down-migration.
-- threat_intel_evidence_json is schema v8: bounded JSON evidence returned by
-- the threat store after an exact file hash lookup. It is nullable for all
-- historical detections and migrated additively by
-- _migrate_detection_evidence_column.
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
    triage_enqueued INTEGER NOT NULL DEFAULT 0,
    sha1 TEXT,
    md5 TEXT,
    threat_family TEXT,
    intel_source TEXT,
    intel_confidence INTEGER,
    feed_version TEXT,
    threat_intel_evidence_json TEXT
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

-- Hash lookups were full table scans (EXPLAIN QUERY PLAN: "SCAN detections").
-- Both tables are queried by digest when correlating a new scan against prior
-- outcomes, so the digest needs a covering index, not a sequential read.
CREATE INDEX IF NOT EXISTS idx_detections_sha256 ON detections(sha256);
CREATE INDEX IF NOT EXISTS idx_quarantine_sha256 ON quarantine_items(sha256);
"""

# Schema v7: provenance columns on `detections` so a detection can carry the
# intel record that produced it. Purely additive -- every column is nullable
# with no default rewrite, so an existing v6 database keeps all of its rows.
#
# Down-migration (SQLite >= 3.35):
#   ALTER TABLE detections DROP COLUMN sha1;
#   ALTER TABLE detections DROP COLUMN md5;
#   ALTER TABLE detections DROP COLUMN threat_family;
#   ALTER TABLE detections DROP COLUMN intel_source;
#   ALTER TABLE detections DROP COLUMN intel_confidence;
#   ALTER TABLE detections DROP COLUMN feed_version;
#   DROP INDEX idx_detections_sha256; DROP INDEX idx_quarantine_sha256;
#   DELETE FROM schema_version; INSERT INTO schema_version VALUES (6);
_DETECTION_INTEL_COLUMNS = {
    "sha1": "TEXT",
    "md5": "TEXT",
    "threat_family": "TEXT",
    "intel_source": "TEXT",
    "intel_confidence": "INTEGER",
    "feed_version": "TEXT",
}

_DETECTION_EVIDENCE_COLUMNS = {"threat_intel_evidence_json": "TEXT"}


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
    intel_evidence: Optional[ThreatIntelEvidence] = None


def _encode_intel_evidence(evidence: Optional[ThreatIntelEvidence]) -> Optional[str]:
    if evidence is None:
        return None
    value = json.dumps(asdict(evidence), separators=(",", ":"), ensure_ascii=True)
    if len(value) > 8192:
        raise ValueError("threat intelligence evidence exceeds the storage limit")
    return value


def _decode_intel_evidence(raw: Optional[str]) -> Optional[ThreatIntelEvidence]:
    if not raw:
        return None
    try:
        if len(raw) > 8192:
            raise ValueError("stored evidence exceeds the storage limit")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("stored evidence must be an object")
        allowed = {
            "indicator_type", "indicator_value", "source", "verification", "confidence",
            "severity", "feed_version", "first_seen", "last_seen", "freshness",
            "corroborations", "block_eligible", "decision_reason",
        }
        return ThreatIntelEvidence(**{key: item for key, item in value.items() if key in allowed})
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        LOGGER.warning("Ignoring malformed persisted threat-intelligence evidence: %s", exc)
        return None


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
                # A crash midway must leave the prior table and version intact
                # so the migration can be retried safely on the next startup.
                # Each step is gated on the version that introduced it, so a v6
                # database is not put through the v6 scan_jobs rebuild again.
                conn.execute("BEGIN IMMEDIATE")
                if row[0] < 6:
                    self._migrate_scan_jobs_partial_state(conn)
                if row[0] < 7:
                    self._migrate_detection_intel_columns(conn)
                if row[0] < 8:
                    self._migrate_detection_evidence_column(conn)
                conn.execute("DELETE FROM schema_version")
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (DB_SCHEMA_VERSION,))
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            raise

    @staticmethod
    def _migrate_detection_intel_columns(conn: sqlite3.Connection) -> None:
        """Add nullable intel-provenance columns without rewriting any row."""
        existing = {row[1] for row in conn.execute("PRAGMA table_info(detections)")}
        for name, declaration in _DETECTION_INTEL_COLUMNS.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE detections ADD COLUMN {name} {declaration}")

    @staticmethod
    def _migrate_detection_evidence_column(conn: sqlite3.Connection) -> None:
        existing = {row[1] for row in conn.execute("PRAGMA table_info(detections)")}
        for name, declaration in _DETECTION_EVIDENCE_COLUMNS.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE detections ADD COLUMN {name} {declaration}")

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
                 file_type, size_bytes, file_path, created_at, triage_enqueued,
                 threat_intel_evidence_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    _encode_intel_evidence(record.intel_evidence),
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
            intel_evidence=_decode_intel_evidence(row["threat_intel_evidence_json"]),
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


# ---------------------------------------------------------------------------
# Threat-intelligence indicator store
#
# This lives in its own SQLite file, deliberately apart from protection.db:
#
#   * it is rebuilt wholesale from upstream feeds, so it must be replaceable by
#     an atomic file rename without risking the detection/quarantine ledger;
#   * it is the only table expected to reach millions of rows, and a corrupt or
#     half-written feed generation must never be able to take the audit trail
#     with it;
#   * a rollback to the previous generation has to be a file swap, not a
#     row-level undo of an interrupted bulk load.
# ---------------------------------------------------------------------------

INTEL_SCHEMA_VERSION = 1

#: Indicator types that identify exact file content. Only these can ever carry
#: an automatic block, because a digest match is proof of byte-for-byte
#: identity with an analysed sample.
HASH_INDICATOR_TYPES = ("sha256", "sha1", "md5")

#: Indicator types that merely describe where a file came from or talked to.
#: A domain, IP, or URL appearing in a feed is an observation about shared
#: infrastructure -- CDNs, compromised hosts, link shorteners and parked
#: domains all turn up in feeds -- so these are never sufficient on their own
#: to block. They can raise suspicion and feed triage; they cannot deny I/O.
NETWORK_INDICATOR_TYPES = ("domain", "ip", "url")

INDICATOR_TYPES = HASH_INDICATOR_TYPES + NETWORK_INDICATOR_TYPES

#: Confidence that a record describes a genuine threat, in ascending order.
#:   retracted    -- the source withdrew it; treat as a negative signal
#:   unverified   -- provenance unknown; advisory only
#:   reported     -- exactly one source lists it, with no analysis behind it
#:   corroborated -- two or more independent sources agree
#:   confirmed    -- the source analysed the sample itself and published its hash
VERIFICATION_STATUSES = ("retracted", "unverified", "reported", "corroborated", "confirmed")

#: Verification levels that may carry an automatic block.
BLOCK_ELIGIBLE_VERIFICATION = ("corroborated", "confirmed")

#: Minimum normalised confidence (0-100) for an automatic block.
DEFAULT_MIN_BLOCK_CONFIDENCE = 85

SEVERITIES = ("critical", "high", "medium", "low", "info")

_HEX_LENGTH_TO_TYPE = {64: "sha256", 40: "sha1", 32: "md5"}


@dataclass(frozen=True, slots=True)
class SourceTrust:
    """What a given feed is allowed to assert, independent of what it claims.

    A feed does not get to set its own trust level. ``max_verification`` caps
    whatever the feed asserts, and ``hash_authoritative`` records whether the
    operator actually analyses samples (and may therefore say "confirmed" about
    a file hash) or merely aggregates reports from others.
    """

    source: str
    max_verification: str
    default_confidence: int
    hash_authoritative: bool
    license_note: str

    def __post_init__(self) -> None:
        if self.max_verification not in VERIFICATION_STATUSES:
            raise ValueError(f"unknown verification status: {self.max_verification!r}")
        if not 0 <= self.default_confidence <= 100:
            raise ValueError("default_confidence must be 0-100")


#: Trust registry. Anything absent is treated as untrusted (see
#: ``trust_for_source``) rather than silently granted a default, so adding a
#: feed is an explicit decision with a recorded licence.
SOURCE_TRUST: dict[str, SourceTrust] = {
    "abusech_malwarebazaar": SourceTrust(
        source="abusech_malwarebazaar",
        # MalwareBazaar publishes hashes of samples it actually holds and has
        # run through its own analysis pipeline, so a file hash from it is
        # first-hand evidence rather than hearsay.
        max_verification="confirmed",
        default_confidence=90,
        hash_authoritative=True,
        license_note="CC0 1.0 Universal (public domain). Metadata/hashes only; "
                     "sample downloads are deliberately never requested.",
    ),
    "abusech_threatfox": SourceTrust(
        source="abusech_threatfox",
        # ThreatFox aggregates community-submitted IOCs with a per-submitter
        # confidence. Aggregated reports are not first-hand analysis.
        max_verification="reported",
        default_confidence=50,
        hash_authoritative=False,
        license_note="CC0 1.0 Universal (public domain). Metadata only.",
    ),
    "abusech_urlhaus": SourceTrust(
        source="abusech_urlhaus",
        max_verification="reported",
        default_confidence=50,
        hash_authoritative=False,
        license_note="CC0 1.0 Universal (public domain). URL metadata only; "
                     "payload URLs are recorded, never fetched.",
    ),
    "abusech_feodotracker": SourceTrust(
        source="abusech_feodotracker",
        max_verification="reported",
        default_confidence=60,
        hash_authoritative=False,
        license_note="CC0 1.0 Universal (public domain). Botnet C2 IPs only.",
    ),
    "virustotal": SourceTrust(
        source="virustotal",
        max_verification="corroborated",
        default_confidence=80,
        hash_authoritative=False,
        license_note="VirusTotal Terms of Service. Redistribution of enrichment "
                     "data is restricted; cache locally, do not republish.",
    ),
    "otx": SourceTrust(
        source="otx",
        max_verification="reported",
        default_confidence=40,
        hash_authoritative=False,
        license_note="AlienVault OTX API terms. Community pulses; attribution required.",
    ),
    "stai_signed_rules": SourceTrust(
        source="stai_signed_rules",
        max_verification="confirmed",
        default_confidence=100,
        hash_authoritative=True,
        license_note="First-party, Ed25519-signed rule package.",
    ),
    "synthetic_benchmark": SourceTrust(
        source="synthetic_benchmark",
        # Fabricated rows exist only to measure index behaviour. They are
        # pinned to the lowest verification so that even if one leaked into a
        # production file it could never produce a block.
        max_verification="unverified",
        default_confidence=0,
        hash_authoritative=False,
        license_note="SYNTHETIC. Generated locally for latency benchmarking. "
                     "Not threat intelligence. Never ship in a detection database.",
    ),
}

#: How long a record from a source stays actionable without being re-seen.
#: Infrastructure indicators rot fast (an IP is reassigned); a file hash does
#: not stop identifying that file, so hash feeds get a long window.
DEFAULT_FRESHNESS_TTL_HOURS: dict[str, int] = {
    "sha256": 24 * 365,
    "sha1": 24 * 365,
    "md5": 24 * 365,
    "domain": 24 * 30,
    "ip": 24 * 7,
    "url": 24 * 14,
}


def trust_for_source(source: str) -> SourceTrust:
    """Return the registered trust for a source, or an untrusted placeholder.

    An unregistered feed is capped at ``unverified`` with zero confidence, so
    plugging in a new feed cannot grant it blocking power by accident.
    """
    known = SOURCE_TRUST.get(source)
    if known is not None:
        return known
    return SourceTrust(
        source=source,
        max_verification="unverified",
        default_confidence=0,
        hash_authoritative=False,
        license_note="UNREGISTERED SOURCE -- no licence recorded, treated as untrusted.",
    )


def normalise_hash(value: str) -> tuple[str, str] | None:
    """Return ``(indicator_type, lowercased digest)`` for a hex digest."""
    candidate = str(value).strip().lower()
    indicator_type = _HEX_LENGTH_TO_TYPE.get(len(candidate))
    if indicator_type is None:
        return None
    try:
        int(candidate, 16)
    except ValueError:
        return None
    return indicator_type, candidate


INTEL_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS intel_schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS intel_indicators (
    indicator_id    INTEGER PRIMARY KEY,
    indicator_type  TEXT NOT NULL CHECK(indicator_type IN
                        ('sha256', 'sha1', 'md5', 'domain', 'ip', 'url')),
    indicator_value TEXT NOT NULL,
    -- Cross-hash columns let one row answer a lookup by any digest the
    -- scanner happens to have computed for the same file.
    sha256          TEXT,
    sha1            TEXT,
    md5             TEXT,
    threat_family   TEXT,
    confidence      INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100),
    severity        TEXT NOT NULL CHECK(severity IN
                        ('critical', 'high', 'medium', 'low', 'info')),
    source          TEXT NOT NULL,
    source_timestamp TEXT,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    verification    TEXT NOT NULL CHECK(verification IN
                        ('retracted', 'unverified', 'reported', 'corroborated', 'confirmed')),
    freshness_ttl_hours INTEGER NOT NULL CHECK(freshness_ttl_hours > 0),
    feed_version    TEXT NOT NULL,
    corroborations  INTEGER NOT NULL DEFAULT 1 CHECK(corroborations >= 1),
    -- 1 marks a fabricated benchmark row. A production store refuses to hold
    -- these at all; the column exists so that a leak is detectable rather
    -- than indistinguishable from real intelligence.
    synthetic       INTEGER NOT NULL DEFAULT 0 CHECK(synthetic IN (0, 1)),
    UNIQUE(source, indicator_type, indicator_value)
);

-- Without these, every digest lookup is "SCAN intel_indicators": a sequential
-- read of the whole table. These turn it into a B-tree SEARCH.
CREATE INDEX IF NOT EXISTS idx_intel_type_value
    ON intel_indicators(indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS idx_intel_sha256 ON intel_indicators(sha256)
    WHERE sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_intel_sha1 ON intel_indicators(sha1)
    WHERE sha1 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_intel_md5 ON intel_indicators(md5)
    WHERE md5 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_intel_family ON intel_indicators(threat_family)
    WHERE threat_family IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_intel_last_seen ON intel_indicators(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_intel_feed_version ON intel_indicators(feed_version);

CREATE TABLE IF NOT EXISTS intel_feed_runs (
    run_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT NOT NULL,
    feed_version TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    completed_at TEXT,
    inserted     INTEGER NOT NULL DEFAULT 0,
    updated      INTEGER NOT NULL DEFAULT 0,
    rejected     INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL CHECK(status IN ('running', 'completed', 'failed')),
    error        TEXT
);

CREATE INDEX IF NOT EXISTS idx_intel_feed_runs_source
    ON intel_feed_runs(source, started_at DESC);
"""


@dataclass(frozen=True, slots=True)
class IndicatorRecord:
    """One normalised indicator, carrying its own provenance and trust."""

    indicator_type: str
    indicator_value: str
    source: str
    confidence: int
    severity: str
    verification: str
    feed_version: str
    first_seen: str
    last_seen: str
    sha256: Optional[str] = None
    sha1: Optional[str] = None
    md5: Optional[str] = None
    threat_family: Optional[str] = None
    source_timestamp: Optional[str] = None
    freshness_ttl_hours: Optional[int] = None
    corroborations: int = 1
    synthetic: bool = False

    def freshness(self, *, now: Optional[datetime] = None) -> str:
        """Classify age as fresh / aging / stale / expired from ``last_seen``."""
        ttl = self.freshness_ttl_hours or DEFAULT_FRESHNESS_TTL_HOURS.get(
            self.indicator_type, 24 * 30
        )
        reference = now or datetime.now()
        try:
            seen = datetime.fromisoformat(self.last_seen)
        except (TypeError, ValueError):
            # An unparseable timestamp is not evidence of freshness.
            return "expired"
        if seen.tzinfo is not None:
            seen = seen.replace(tzinfo=None)
        if reference.tzinfo is not None:
            reference = reference.replace(tzinfo=None)
        age_hours = (reference - seen).total_seconds() / 3600.0
        if age_hours < 0:
            # A future timestamp is a feed bug, not a very fresh record.
            return "stale"
        if age_hours <= ttl * 0.5:
            return "fresh"
        if age_hours <= ttl:
            return "aging"
        if age_hours <= ttl * 2:
            return "stale"
        return "expired"


@dataclass(frozen=True, slots=True)
class BlockDecision:
    """Whether intel alone justifies denying I/O, and why."""

    block: bool
    verdict: Literal["block", "suspicious", "unknown"]
    reason: str
    record: Optional[IndicatorRecord] = None


class SyntheticDataRejected(ValueError):
    """A benchmark row was offered to a production detection database."""


class IntelIntegrityError(RuntimeError):
    """The intel database failed its integrity or schema check."""


class ThreatIntelStore:
    """Indexed, atomically replaceable indicator database.

    ``allow_synthetic`` must be set explicitly to hold fabricated benchmark
    rows. A production store leaves it at ``False`` and rejects them outright,
    so a benchmark fixture cannot drift into the detection path.
    """

    def __init__(
        self,
        database_path: Path,
        *,
        allow_synthetic: bool = False,
        min_block_confidence: int = DEFAULT_MIN_BLOCK_CONFIDENCE,
    ) -> None:
        self._path = Path(database_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._allow_synthetic = bool(allow_synthetic)
        self._min_block_confidence = int(min_block_confidence)
        self._local = threading.local()
        # A corrupt file must not stop the object from being constructed: the
        # service has to come up, report itself degraded, and get a chance to
        # run recover_if_corrupt(). The error is held for verify_integrity()
        # to surface rather than discarded.
        self._init_error: Optional[str] = None
        self._init_db()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def allows_synthetic(self) -> bool:
        return self._allow_synthetic

    @property
    def min_block_confidence(self) -> int:
        return self._min_block_confidence

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _init_db(self) -> None:
        conn = self._get_conn()
        try:
            conn.executescript(INTEL_SCHEMA_SQL)
            row = conn.execute("SELECT version FROM intel_schema_version").fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO intel_schema_version (version) VALUES (?)",
                    (INTEL_SCHEMA_VERSION,),
                )
            conn.commit()
            self._init_error = None
        except sqlite3.DatabaseError as exc:
            # "file is not a database" / "database disk image is malformed":
            # the file on disk is unusable. Record it and let the caller decide
            # between rolling back and rebuilding.
            try:
                conn.rollback()
            except sqlite3.DatabaseError:
                pass
            self.close()
            self._init_error = str(exc)

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    # -- ingestion ---------------------------------------------------------

    def upsert_indicators(
        self,
        records: Sequence[IndicatorRecord],
        *,
        feed_version: Optional[str] = None,
    ) -> dict[str, int]:
        """Insert or merge indicators, applying the source trust ceiling.

        Trust is recomputed here rather than taken from the record, so a feed
        parser cannot grant itself a verification level. Re-seeing an indicator
        from a *different* source escalates it to ``corroborated``: independent
        agreement is the only thing that upgrades a mere report.
        """
        counters = {"inserted": 0, "updated": 0, "rejected": 0, "corroborated": 0}
        if not records:
            return counters

        now = datetime.now().isoformat(timespec="seconds")
        with self._transaction() as conn:
            for record in records:
                try:
                    prepared = self._prepare(record, feed_version, now)
                except (SyntheticDataRejected, ValueError):
                    counters["rejected"] += 1
                    continue

                existing = conn.execute(
                    """
                    SELECT indicator_id, first_seen FROM intel_indicators
                    WHERE source = ? AND indicator_type = ? AND indicator_value = ?
                    """,
                    (prepared["source"], prepared["indicator_type"], prepared["indicator_value"]),
                ).fetchone()

                # Independent agreement from any other source escalates this
                # indicator, regardless of which row we are writing now.
                others = int(
                    conn.execute(
                        """
                        SELECT COUNT(DISTINCT source) FROM intel_indicators
                        WHERE indicator_type = ? AND indicator_value = ? AND source <> ?
                          AND verification <> 'retracted' AND synthetic = 0
                        """,
                        (
                            prepared["indicator_type"],
                            prepared["indicator_value"],
                            prepared["source"],
                        ),
                    ).fetchone()[0]
                )
                if others and not prepared["synthetic"] and prepared["verification"] == "reported":
                    prepared["verification"] = "corroborated"
                    counters["corroborated"] += 1
                prepared["corroborations"] = others + 1

                if existing is None:
                    conn.execute(
                        """
                        INSERT INTO intel_indicators (
                            indicator_type, indicator_value, sha256, sha1, md5,
                            threat_family, confidence, severity, source, source_timestamp,
                            first_seen, last_seen, verification, freshness_ttl_hours,
                            feed_version, corroborations, synthetic
                        ) VALUES (
                            :indicator_type, :indicator_value, :sha256, :sha1, :md5,
                            :threat_family, :confidence, :severity, :source, :source_timestamp,
                            :first_seen, :last_seen, :verification, :freshness_ttl_hours,
                            :feed_version, :corroborations, :synthetic
                        )
                        """,
                        prepared,
                    )
                    counters["inserted"] += 1
                else:
                    # first_seen is the earliest sighting and never moves forward.
                    prepared["first_seen"] = existing["first_seen"]
                    prepared["indicator_id"] = existing["indicator_id"]
                    conn.execute(
                        """
                        UPDATE intel_indicators SET
                            sha256 = COALESCE(:sha256, sha256),
                            sha1 = COALESCE(:sha1, sha1),
                            md5 = COALESCE(:md5, md5),
                            threat_family = COALESCE(:threat_family, threat_family),
                            confidence = :confidence,
                            severity = :severity,
                            source_timestamp = COALESCE(:source_timestamp, source_timestamp),
                            last_seen = :last_seen,
                            verification = :verification,
                            freshness_ttl_hours = :freshness_ttl_hours,
                            feed_version = :feed_version,
                            corroborations = :corroborations
                        WHERE indicator_id = :indicator_id
                        """,
                        prepared,
                    )
                    counters["updated"] += 1

                # Propagate the escalation to the sibling rows so a later
                # lookup of any one of them sees the corroborated status.
                if prepared["verification"] == "corroborated":
                    conn.execute(
                        """
                        UPDATE intel_indicators
                        SET verification = 'corroborated', corroborations = :corroborations
                        WHERE indicator_type = :indicator_type
                          AND indicator_value = :indicator_value
                          AND verification = 'reported' AND synthetic = 0
                        """,
                        prepared,
                    )
        return counters

    def bulk_load_hashes(
        self,
        digests: Iterable[str],
        *,
        source: str,
        feed_version: str,
        severity: str = "high",
        verification: str = "confirmed",
        threat_family: Optional[str] = None,
        synthetic: bool = False,
        batch_size: int = 20_000,
    ) -> dict[str, int]:
        """Bulk-load a hash-only export in batched ``executemany`` inserts.

        ``upsert_indicators`` issues two SELECTs per row to compute
        corroboration, which is correct for incremental feed merges but costs
        millions of queries on a full generation rebuild. This path is for
        building a fresh generation in a staging store: the trust ceiling is
        resolved once (the source is constant), and ``INSERT OR IGNORE`` makes
        a duplicate digest a no-op rather than a failed transaction.
        """
        if synthetic and not self._allow_synthetic:
            raise SyntheticDataRejected(
                "this store is a production detection database and refuses synthetic rows"
            )
        if severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {severity!r}")

        trust = trust_for_source(source)
        asserted = verification if verification in VERIFICATION_STATUSES else "unverified"
        if VERIFICATION_STATUSES.index(asserted) > VERIFICATION_STATUSES.index(
            trust.max_verification
        ):
            asserted = trust.max_verification
        if asserted == "confirmed" and not trust.hash_authoritative:
            asserted = "corroborated" if trust.max_verification == "confirmed" else trust.max_verification
        confidence = trust.default_confidence
        if synthetic:
            asserted, confidence = "unverified", 0

        now = datetime.now().isoformat(timespec="seconds")
        statement = """
            INSERT OR IGNORE INTO intel_indicators (
                indicator_type, indicator_value, sha256, sha1, md5, threat_family,
                confidence, severity, source, source_timestamp, first_seen, last_seen,
                verification, freshness_ttl_hours, feed_version, corroborations, synthetic
            ) VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, 1, ?)
        """
        counters = {"inserted": 0, "rejected": 0}
        conn = self._get_conn()
        batch: list[tuple[Any, ...]] = []
        synthetic_flag = 1 if synthetic else 0

        def flush() -> None:
            if not batch:
                return
            cursor = conn.executemany(statement, batch)
            counters["inserted"] += cursor.rowcount if cursor.rowcount > 0 else 0
            batch.clear()
            # Commit per batch rather than wrapping a million rows in one
            # transaction: a single transaction grows the WAL without bound
            # (observed: 437 MB and climbing on a 1.15M-row load) because it
            # can never checkpoint. A crash mid-load leaves a short staging
            # file, which promote_staging already refuses via min_rows.
            conn.commit()

        # Secondary indexes are rebuilt once at the end instead of being
        # maintained per row. The UNIQUE(source, type, value) constraint index
        # stays in place throughout, so INSERT OR IGNORE keeps the load
        # idempotent even while the lookup indexes are absent.
        secondary_indexes = [
            row[0]
            for row in conn.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'index' "
                "AND tbl_name = 'intel_indicators' AND sql IS NOT NULL"
            )
        ]
        index_names = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' "
                "AND tbl_name = 'intel_indicators' AND sql IS NOT NULL"
            )
        ]
        try:
            for name in index_names:
                conn.execute(f"DROP INDEX IF EXISTS {name}")
            conn.commit()
            for raw in digests:
                normalised = normalise_hash(str(raw))
                if normalised is None:
                    counters["rejected"] += 1
                    continue
                indicator_type, value = normalised
                ttl = DEFAULT_FRESHNESS_TTL_HOURS[indicator_type]
                batch.append(
                    (
                        indicator_type, value, value, threat_family, confidence, severity,
                        source, now, now, asserted, ttl, feed_version, synthetic_flag,
                    )
                )
                if len(batch) >= batch_size:
                    flush()
            flush()
        except Exception:
            conn.rollback()
            raise
        finally:
            # Restore the indexes even on failure; a staging file without them
            # would silently serve every lookup as a table scan.
            for sql in secondary_indexes:
                conn.execute(sql)
            conn.commit()
        counters["verification"] = asserted  # type: ignore[assignment]
        counters["confidence"] = confidence
        return counters

    def _prepare(
        self,
        record: IndicatorRecord,
        feed_version: Optional[str],
        now: str,
    ) -> dict[str, Any]:
        if record.indicator_type not in INDICATOR_TYPES:
            raise ValueError(f"unknown indicator_type: {record.indicator_type!r}")
        if record.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {record.severity!r}")

        synthetic = bool(record.synthetic)
        if synthetic and not self._allow_synthetic:
            raise SyntheticDataRejected(
                "this store is a production detection database and refuses synthetic rows"
            )

        value = str(record.indicator_value).strip().lower()
        if not value:
            raise ValueError("indicator_value is empty")
        if record.indicator_type in HASH_INDICATOR_TYPES:
            normalised = normalise_hash(value)
            if normalised is None or normalised[0] != record.indicator_type:
                raise ValueError(
                    f"{record.indicator_value!r} is not a valid {record.indicator_type} digest"
                )
            value = normalised[1]

        trust = trust_for_source(record.source)

        # Cap the asserted verification at what this source is allowed to say,
        # and additionally refuse "confirmed" from a source that does not do
        # its own sample analysis.
        asserted = (
            record.verification if record.verification in VERIFICATION_STATUSES else "unverified"
        )
        ceiling = trust.max_verification
        if VERIFICATION_STATUSES.index(asserted) > VERIFICATION_STATUSES.index(ceiling):
            asserted = ceiling
        if asserted == "confirmed" and not (
            trust.hash_authoritative and record.indicator_type in HASH_INDICATOR_TYPES
        ):
            asserted = "corroborated" if ceiling == "confirmed" else ceiling

        confidence = (
            record.confidence if record.confidence is not None else trust.default_confidence
        )
        confidence = max(0, min(100, int(confidence)))
        # A feed cannot claim more confidence than its trust tier allows.
        confidence = min(confidence, trust.default_confidence)
        if synthetic:
            confidence = 0
            asserted = "unverified"

        hashes = {"sha256": record.sha256, "sha1": record.sha1, "md5": record.md5}
        if record.indicator_type in HASH_INDICATOR_TYPES:
            hashes[record.indicator_type] = value
        for key, digest in list(hashes.items()):
            if digest is None:
                continue
            normalised = normalise_hash(str(digest))
            hashes[key] = normalised[1] if normalised and normalised[0] == key else None

        ttl = record.freshness_ttl_hours or DEFAULT_FRESHNESS_TTL_HOURS.get(
            record.indicator_type, 24 * 30
        )

        return {
            "indicator_type": record.indicator_type,
            "indicator_value": value,
            "sha256": hashes["sha256"],
            "sha1": hashes["sha1"],
            "md5": hashes["md5"],
            "threat_family": record.threat_family or None,
            "confidence": confidence,
            "severity": record.severity,
            "source": record.source,
            "source_timestamp": record.source_timestamp,
            "first_seen": record.first_seen or now,
            "last_seen": record.last_seen or now,
            "verification": asserted,
            "freshness_ttl_hours": int(ttl),
            "feed_version": feed_version or record.feed_version or "unversioned",
            "corroborations": max(1, int(record.corroborations)),
            "synthetic": 1 if synthetic else 0,
        }

    # -- lookup ------------------------------------------------------------

    def lookup_hash(self, digest: str) -> Optional[IndicatorRecord]:
        """Return the strongest record for a digest, or None.

        The digest's length selects the column, so each lookup hits one index.
        """
        normalised = normalise_hash(digest)
        if normalised is None:
            return None
        column, value = normalised
        with self._get_conn() as conn:
            row = conn.execute(
                f"""
                SELECT * FROM intel_indicators
                WHERE {column} = ?
                ORDER BY CASE verification
                             WHEN 'confirmed' THEN 0 WHEN 'corroborated' THEN 1
                             WHEN 'reported' THEN 2 WHEN 'unverified' THEN 3 ELSE 4 END,
                         confidence DESC, last_seen DESC
                LIMIT 1
                """,
                (value,),
            ).fetchone()
        return self._row_to_indicator(row) if row else None

    def lookup_hashes(self, digests: Sequence[str]) -> dict[str, IndicatorRecord]:
        """Batch digest lookup. Misses are simply absent from the mapping."""
        found: dict[str, IndicatorRecord] = {}
        for digest in digests:
            record = self.lookup_hash(digest)
            if record is not None:
                found[record.indicator_value] = record
        return found

    def lookup_network_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[IndicatorRecord]:
        if indicator_type not in NETWORK_INDICATOR_TYPES:
            raise ValueError(f"not a network indicator type: {indicator_type!r}")
        with self._get_conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM intel_indicators
                WHERE indicator_type = ? AND indicator_value = ?
                ORDER BY confidence DESC, last_seen DESC LIMIT 1
                """,
                (indicator_type, str(value).strip().lower()),
            ).fetchone()
        return self._row_to_indicator(row) if row else None

    # -- the confidence model ---------------------------------------------

    def block_decision(
        self,
        indicator_type: str,
        value: str,
        *,
        now: Optional[datetime] = None,
    ) -> BlockDecision:
        """Decide whether intel alone justifies blocking this indicator.

        This is the gate that stops "it was in a feed" from meaning "block it".
        Every negative path returns ``suspicious`` or ``unknown`` -- never
        ``clean`` -- because the absence of a block is not a clean bill of
        health, and the caller must not be able to read it as one.
        """
        if indicator_type in NETWORK_INDICATOR_TYPES:
            record = self.lookup_network_indicator(indicator_type, value)
            if record is None:
                return BlockDecision(False, "unknown", "no intel record for this indicator")
            return BlockDecision(
                False,
                "suspicious",
                # The structural rule: infrastructure is shared, so presence in
                # a feed is evidence about the infrastructure, not about this
                # file or this connection.
                f"{indicator_type} indicators are never auto-blocked on feed presence "
                f"alone (source={record.source}, verification={record.verification}, "
                f"confidence={record.confidence}); route to triage",
                record,
            )

        record = self.lookup_hash(value)
        if record is None:
            return BlockDecision(False, "unknown", "no intel record for this digest")

        if record.synthetic:
            return BlockDecision(
                False,
                "unknown",
                "record is a synthetic benchmark row, not intelligence",
                record,
            )
        if record.verification == "retracted":
            return BlockDecision(False, "unknown", "source retracted this indicator", record)
        if record.verification not in BLOCK_ELIGIBLE_VERIFICATION:
            return BlockDecision(
                False,
                "suspicious",
                f"verification={record.verification} is below the "
                f"{'/'.join(BLOCK_ELIGIBLE_VERIFICATION)} bar for an automatic block",
                record,
            )
        if record.confidence < self._min_block_confidence:
            return BlockDecision(
                False,
                "suspicious",
                f"confidence={record.confidence} is below the "
                f"{self._min_block_confidence} block threshold",
                record,
            )
        freshness = record.freshness(now=now)
        if freshness == "expired":
            return BlockDecision(
                False,
                "suspicious",
                f"record is {freshness} (last_seen={record.last_seen})",
                record,
            )

        return BlockDecision(
            True,
            "block",
            f"exact {record.indicator_type} match, verification={record.verification}, "
            f"confidence={record.confidence}, freshness={freshness}, source={record.source}",
            record,
        )

    # -- counts and statistics --------------------------------------------

    def count_unique_hashes(self, *, include_synthetic: bool = False) -> int:
        """Count distinct malicious file hashes across all three digest types."""
        clause = "" if include_synthetic else "AND synthetic = 0"
        with self._get_conn() as conn:
            return int(
                conn.execute(
                    f"""
                    SELECT COUNT(*) FROM (
                        SELECT DISTINCT indicator_type, indicator_value
                        FROM intel_indicators
                        WHERE indicator_type IN ('sha256', 'sha1', 'md5')
                          AND verification <> 'retracted' {clause}
                    )
                    """
                ).fetchone()[0]
            )

    def count_block_eligible_hashes(self) -> int:
        """Hashes that would actually produce a block, not merely be present."""
        with self._get_conn() as conn:
            return int(
                conn.execute(
                    """
                    SELECT COUNT(*) FROM (
                        SELECT DISTINCT indicator_type, indicator_value
                        FROM intel_indicators
                        WHERE indicator_type IN ('sha256', 'sha1', 'md5')
                          AND verification IN ('confirmed', 'corroborated')
                          AND confidence >= ? AND synthetic = 0
                    )
                    """,
                    (self._min_block_confidence,),
                ).fetchone()[0]
            )

    def stats(self) -> dict[str, Any]:
        with self._get_conn() as conn:
            total = int(conn.execute("SELECT COUNT(*) FROM intel_indicators").fetchone()[0])
            synthetic = int(
                conn.execute(
                    "SELECT COUNT(*) FROM intel_indicators WHERE synthetic = 1"
                ).fetchone()[0]
            )
            by_type = {
                row["indicator_type"]: row["n"]
                for row in conn.execute(
                    "SELECT indicator_type, COUNT(*) AS n FROM intel_indicators "
                    "GROUP BY indicator_type"
                )
            }
            by_source = {
                row["source"]: row["n"]
                for row in conn.execute(
                    "SELECT source, COUNT(*) AS n FROM intel_indicators GROUP BY source"
                )
            }
            by_verification = {
                row["verification"]: row["n"]
                for row in conn.execute(
                    "SELECT verification, COUNT(*) AS n FROM intel_indicators "
                    "GROUP BY verification"
                )
            }
            feed_versions = [
                row["feed_version"]
                for row in conn.execute(
                    "SELECT DISTINCT feed_version FROM intel_indicators ORDER BY feed_version"
                )
            ]
        return {
            "database": str(self._path),
            "total_rows": total,
            "synthetic_rows": synthetic,
            "unique_hashes": self.count_unique_hashes(),
            "block_eligible_hashes": self.count_block_eligible_hashes(),
            "by_indicator_type": by_type,
            "by_source": by_source,
            "by_verification": by_verification,
            "feed_versions": feed_versions,
            "allows_synthetic": self._allow_synthetic,
        }

    # -- feed run bookkeeping ---------------------------------------------

    def start_feed_run(self, source: str, feed_version: str) -> int:
        with self._transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO intel_feed_runs (source, feed_version, started_at, status)
                VALUES (?, ?, ?, 'running')
                """,
                (source, feed_version, datetime.now().isoformat(timespec="seconds")),
            )
            return int(cursor.lastrowid or 0)

    def finish_feed_run(
        self,
        run_id: int,
        *,
        status: Literal["completed", "failed"],
        inserted: int = 0,
        updated: int = 0,
        rejected: int = 0,
        error: Optional[str] = None,
    ) -> None:
        with self._transaction() as conn:
            conn.execute(
                """
                UPDATE intel_feed_runs
                SET status = ?, inserted = ?, updated = ?, rejected = ?, error = ?,
                    completed_at = ?
                WHERE run_id = ?
                """,
                (
                    status,
                    inserted,
                    updated,
                    rejected,
                    str(error)[:512] if error else None,
                    datetime.now().isoformat(timespec="seconds"),
                    run_id,
                ),
            )

    def last_feed_run(self, source: str) -> Optional[dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM intel_feed_runs WHERE source = ? "
                "ORDER BY started_at DESC, run_id DESC LIMIT 1",
                (source,),
            ).fetchone()
        return dict(row) if row else None

    # -- integrity, atomic update, rollback -------------------------------

    def verify_integrity(self) -> dict[str, Any]:
        """Run SQLite's own structural checks plus our schema invariants."""
        problems: list[str] = []
        version: Optional[int] = None
        if self._init_error is not None:
            return {
                "ok": False,
                "schema_version": None,
                "problems": [f"database is unreadable: {self._init_error}"],
            }
        conn = self._get_conn()
        try:
            integrity = [r[0] for r in conn.execute("PRAGMA integrity_check")]
            if integrity != ["ok"]:
                problems.extend(f"integrity_check: {item}" for item in integrity)
            foreign_keys = conn.execute("PRAGMA foreign_key_check").fetchall()
            if foreign_keys:
                problems.append(f"foreign_key_check reported {len(foreign_keys)} violation(s)")
            row = conn.execute("SELECT version FROM intel_schema_version").fetchone()
            version = int(row[0]) if row else None
            if version != INTEL_SCHEMA_VERSION:
                problems.append(f"schema version {version} != expected {INTEL_SCHEMA_VERSION}")
            leaked = int(
                conn.execute(
                    "SELECT COUNT(*) FROM intel_indicators WHERE synthetic = 1"
                ).fetchone()[0]
            )
            if leaked and not self._allow_synthetic:
                problems.append(f"{leaked} synthetic row(s) in a production store")
        except sqlite3.DatabaseError as exc:
            # A corrupt header raises here rather than returning a bad row.
            problems.append(f"database is unreadable: {exc}")
        return {"ok": not problems, "schema_version": version, "problems": problems}

    def staging_path(self) -> Path:
        """Path for a new generation built alongside the live database."""
        return Path(str(self._path) + ".staging")

    def previous_path(self) -> Path:
        """Path holding the generation replaced by the last promotion."""
        return Path(str(self._path) + ".prev")

    @staticmethod
    def _remove_db_files(base: Path) -> None:
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(base) + suffix)
            if candidate.exists():
                candidate.unlink()

    def open_staging(self) -> "ThreatIntelStore":
        """Create an empty staging store to bulk-load a new generation into.

        Loading into a separate file is what makes the update atomic: the live
        database is untouched until ``promote_staging`` renames over it, so a
        crash or a truncated feed leaves the old generation serving lookups.
        """
        staging = self.staging_path()
        self._remove_db_files(staging)
        return ThreatIntelStore(
            staging,
            allow_synthetic=self._allow_synthetic,
            min_block_confidence=self._min_block_confidence,
        )

    def promote_staging(self, *, min_rows: int = 1) -> dict[str, Any]:
        """Swap a verified staging generation in, keeping the old one for rollback.

        Refuses a staging file that fails integrity checks or holds fewer than
        ``min_rows`` rows, so a feed outage that produced an empty download
        cannot silently wipe the detection database.
        """
        staging = self.staging_path()
        if not staging.exists():
            raise IntelIntegrityError("no staging database to promote")

        probe = ThreatIntelStore(
            staging,
            allow_synthetic=self._allow_synthetic,
            min_block_confidence=self._min_block_confidence,
        )
        try:
            report = probe.verify_integrity()
            if not report["ok"]:
                raise IntelIntegrityError(f"staging database rejected: {report['problems']}")
            rows = int(
                probe._get_conn()
                .execute("SELECT COUNT(*) FROM intel_indicators")
                .fetchone()[0]
            )
            if rows < min_rows:
                raise IntelIntegrityError(
                    f"staging database holds {rows} row(s), below the {min_rows} minimum; "
                    "refusing to replace the live database with a short feed"
                )
            # Fold the WAL into the main file so the single rename below carries
            # every committed row.
            probe._get_conn().execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            probe.close()

        previous = self.previous_path()
        self._remove_db_files(previous)
        if self._path.exists():
            self._get_conn().execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.close()
            os.replace(self._path, previous)
        self.close()
        for suffix in ("-wal", "-shm"):
            stale = Path(str(self._path) + suffix)
            if stale.exists():
                stale.unlink()
        os.replace(staging, self._path)
        # The promoted file carries every row; its old sidecar WAL/SHM do not.
        self._remove_db_files(staging)

        self._init_db()
        return {"promoted": True, "rows": rows, "previous": str(previous)}

    def rollback(self) -> dict[str, Any]:
        """Restore the generation replaced by the last promotion."""
        previous = self.previous_path()
        if not previous.exists():
            raise IntelIntegrityError("no previous generation to roll back to")
        self.close()
        failed = Path(str(self._path) + ".rolledback")
        self._remove_db_files(failed)
        if self._path.exists():
            os.replace(self._path, failed)
        for suffix in ("-wal", "-shm"):
            stale = Path(str(self._path) + suffix)
            if stale.exists():
                stale.unlink()
        os.replace(previous, self._path)
        self._init_db()
        report = self.verify_integrity()
        return {"rolled_back": True, "integrity": report, "quarantined": str(failed)}

    def recover_if_corrupt(self) -> dict[str, Any]:
        """Detect corruption and recover by rollback, else by rebuilding empty.

        An unreadable detection database must not take the service down and
        must not be silently treated as "no threats known". The caller learns
        which happened: a rollback preserves the previous generation's rows, a
        rebuild returns an empty store that needs a fresh feed pull.
        """
        report = self.verify_integrity()
        if report["ok"]:
            return {"action": "none", "integrity": report}

        if self.previous_path().exists():
            try:
                rolled = self.rollback()
                if rolled["integrity"]["ok"]:
                    return {"action": "rolled_back", "integrity": rolled["integrity"]}
            except (IntelIntegrityError, OSError, sqlite3.DatabaseError):
                pass

        self.close()
        corrupt = Path(str(self._path) + ".corrupt")
        self._remove_db_files(corrupt)
        if self._path.exists():
            os.replace(self._path, corrupt)
        for suffix in ("-wal", "-shm"):
            stale = Path(str(self._path) + suffix)
            if stale.exists():
                stale.unlink()
        self._init_db()
        return {
            "action": "rebuilt_empty",
            "integrity": self.verify_integrity(),
            "quarantined": str(corrupt),
            "warning": "detection database was rebuilt empty; a feed pull is required "
                       "before hash lookups mean anything",
        }

    @staticmethod
    def _row_to_indicator(row: sqlite3.Row) -> IndicatorRecord:
        return IndicatorRecord(
            indicator_type=row["indicator_type"],
            indicator_value=row["indicator_value"],
            source=row["source"],
            confidence=int(row["confidence"]),
            severity=row["severity"],
            verification=row["verification"],
            feed_version=row["feed_version"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            sha256=row["sha256"],
            sha1=row["sha1"],
            md5=row["md5"],
            threat_family=row["threat_family"],
            source_timestamp=row["source_timestamp"],
            freshness_ttl_hours=int(row["freshness_ttl_hours"]),
            corroborations=int(row["corroborations"]),
            synthetic=bool(row["synthetic"]),
        )
