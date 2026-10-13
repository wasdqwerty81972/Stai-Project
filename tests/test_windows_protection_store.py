"""Durable-store tests for the Windows protection core (plan Task 3).

These pin the spec invariants that the ``ProtectionStore`` must uphold:

* detection, blocked, and quarantined counts stay distinct;
* "Threats Blocked" rises only after a confirmed denied I/O completion
  (never from a mere detection) and is idempotent against replays;
* scan-job progress and cancellation survive a process/store reopen;
* the Windows security reader is read-only and optional.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cyber_os.protection import windows_health
from cyber_os.protection.store import DetectionRecord, ProtectionStore


def _detection(action: str = "block", **overrides) -> DetectionRecord:
    base = dict(
        detection_id=f"det-{action}",
        sha256="a" * 64,
        rule_id="hash-1",
        rule_version="test-1",
        action=action,
        confidence="high" if action == "block" else "low",
        severity="critical" if action == "block" else "medium",
        file_type=".exe",
        size_bytes=1024,
        file_path="C:\\sample.exe",
        created_at="2026-10-12T00:00:00",
        triage_enqueued=False,
    )
    base.update(overrides)
    return DetectionRecord(**base)  # type: ignore[arg-type]


def test_detection_and_action_counts_are_separate(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "p.db")

    store.record_detection(_detection(action="block"))

    counts = store.get_status().counts
    # A block *verdict* is a detection, not a confirmed block or quarantine.
    assert counts["detected"] == 1
    assert counts["blocked"] == 0
    assert counts["quarantined"] == 0


def test_blocked_count_requires_denied_completion(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "p.db")
    store.record_detection(_detection(action="block"))

    # No confirmed denied I/O yet.
    assert store.get_status().counts["blocked"] == 0

    # A non-deny completion must never increment the blocked count.
    assert store.record_filter_completion("req-ok", "STATUS_SUCCESS") is False
    assert store.get_status().counts["blocked"] == 0

    # A real denied I/O completion increments it exactly once...
    assert store.record_filter_completion("req-deny", "STATUS_ACCESS_DENIED") is True
    assert store.get_status().counts["blocked"] == 1

    # ...and a replay of the same completion must not double-count.
    assert store.record_filter_completion("req-deny", "STATUS_ACCESS_DENIED") is False
    assert store.get_status().counts["blocked"] == 1


def test_scan_job_progress_survives_store_reopen(tmp_path: Path) -> None:
    db = tmp_path / "p.db"
    store = ProtectionStore(db)
    store.create_scan_job("job-1", "quick", root_snapshot=["C:\\Users\\demo\\Downloads"])
    store.update_scan_job(
        "job-1", state="running", files_scanned=5, files_total=10, detections=1, errors=0
    )

    reopened = ProtectionStore(db)
    job = reopened.get_scan_job("job-1")

    assert job is not None
    assert (job.state, job.files_scanned, job.files_total, job.detections) == (
        "running",
        5,
        10,
        1,
    )
    assert job.root_snapshot == ["C:\\Users\\demo\\Downloads"]


def test_scan_job_root_snapshot_column_is_added_to_existing_database(tmp_path: Path) -> None:
    import sqlite3

    db = tmp_path / "legacy.db"
    with sqlite3.connect(db) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
            INSERT INTO schema_version (version) VALUES (2);
            CREATE TABLE scan_jobs (
                job_id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                state TEXT NOT NULL,
                files_scanned INTEGER NOT NULL DEFAULT 0,
                files_total INTEGER NOT NULL DEFAULT 0,
                detections INTEGER NOT NULL DEFAULT 0,
                errors INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                error_message TEXT
            );
            INSERT INTO scan_jobs (job_id, scope, state, started_at)
            VALUES ('legacy-job', 'quick', 'completed', '2026-10-01T00:00:00');
            """
        )

    store = ProtectionStore(db)
    job = store.get_scan_job("legacy-job")

    assert job is not None
    assert job.root_snapshot == []
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == 3


def test_scan_cancellation_is_durable(tmp_path: Path) -> None:
    db = tmp_path / "p.db"
    store = ProtectionStore(db)
    store.create_scan_job("job-2", "system")
    store.update_scan_job("job-2", state="running", files_scanned=7, files_total=20)
    store.update_scan_job("job-2", state="cancelled")

    reopened = ProtectionStore(db)
    job = reopened.get_scan_job("job-2")

    assert job is not None
    assert job.state == "cancelled"
    assert job.completed_at is not None
    assert job.files_scanned == 7  # progress at cancellation is preserved


def test_windows_security_status_is_read_only_and_optional(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Optional: on a non-Windows host the reader reports unavailable and must
    # not shell out at all.
    fake_run = MagicMock(side_effect=AssertionError("must not run when unavailable"))
    monkeypatch.setattr(windows_health.platform, "system", lambda: "Linux")
    monkeypatch.setattr(windows_health.subprocess, "run", fake_run)

    status = windows_health.get_windows_security_status()

    assert (status.registered_av_provider, status.defender_mode, status.query_available) == (
        None,
        None,
        False,
    )
    fake_run.assert_not_called()

    # Read-only: the reader must never contain a Defender/Security Center
    # mutation. This guards the brief's "do not silently disable or
    # reconfigure Microsoft Defender" requirement against future edits.
    source = inspect.getsource(windows_health)
    for forbidden in (
        "Set-MpPreference",
        "Add-MpPreference",
        "Remove-MpPreference",
        "Disable-",
        "Set-CimInstance",
        "Set-Service",
        "Stop-Service",
    ):
        assert forbidden not in source, f"windows_health must stay read-only (found {forbidden})"

    # Optional in the status payload when no reading was supplied.
    store = ProtectionStore(tmp_path / "p.db")
    windows_security = store.get_status().windows_security
    assert windows_security["query_available"] is False
    assert windows_security["registered_av_provider"] is None
