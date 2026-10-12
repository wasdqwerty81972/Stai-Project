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
import sqlite3
from datetime import datetime
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
    store.create_scan_job("job-1", "quick")
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


def test_scan_profile_is_per_sid_and_replaces_only_complete_profiles(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "profiles.db")
    sid = "S-1-5-21-1-2-3-1001"
    roots = (("desktop", r"C:\Users\alice\Desktop"),
             ("downloads", r"C:\Users\alice\Downloads"),
             ("startup", r"C:\Users\alice\Startup"))

    profile = store.replace_scan_profile(sid, roots, "2026-10-12T10:00:00")

    assert profile.owner_sid == sid
    assert profile.roots == roots
    assert store.get_scan_profile("S-1-5-21-1-2-3-1002") is None
    with pytest.raises(ValueError, match="three known folders"):
        store.replace_scan_profile(sid, roots[:2], "2026-10-12T11:00:00")
    assert store.get_scan_profile(sid) == profile


def test_scan_job_roots_are_an_immutable_snapshot(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "snapshots.db")
    roots = (("desktop", r"C:\Users\alice\Desktop"),
             ("downloads", r"C:\Users\alice\Downloads"),
             ("startup", r"C:\Users\alice\Startup"))

    job = store.create_scan_job_with_roots("job-profile", "quick", roots)
    store.replace_scan_profile(
        "S-1-5-21-1-2-3-1001",
        (("desktop", r"D:\Redirected\Desktop"),
         ("downloads", r"D:\Redirected\Downloads"),
         ("startup", r"D:\Redirected\Startup")),
        "2026-10-12T12:00:00",
    )

    assert job.source == "interactive"
    assert store.get_scan_job_roots("job-profile") == roots


def test_scan_profile_schema_migration_preserves_existing_jobs(tmp_path: Path) -> None:
    db = tmp_path / "schema-v2.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
        INSERT INTO schema_version VALUES (2);
        CREATE TABLE scan_jobs (
            job_id TEXT PRIMARY KEY, scope TEXT NOT NULL, state TEXT NOT NULL,
            files_scanned INTEGER NOT NULL DEFAULT 0, files_total INTEGER NOT NULL DEFAULT 0,
            detections INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0,
            started_at TEXT NOT NULL, completed_at TEXT, error_message TEXT
        );
        INSERT INTO scan_jobs (job_id, scope, state, started_at)
        VALUES ('legacy-job', 'quick', 'completed', '2026-10-11T10:00:00');
        """
    )
    conn.commit()
    conn.close()

    store = ProtectionStore(db)

    assert store.get_scan_job("legacy-job").state == "completed"
    assert store.get_scan_job_roots("legacy-job") == ()


def test_scan_root_coverage_migration_preserves_snapshots(tmp_path: Path) -> None:
    db = tmp_path / "schema-v4.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
        INSERT INTO schema_version VALUES (4);
        CREATE TABLE scan_jobs (
            job_id TEXT PRIMARY KEY, scope TEXT NOT NULL, state TEXT NOT NULL,
            files_scanned INTEGER NOT NULL DEFAULT 0, files_total INTEGER NOT NULL DEFAULT 0,
            detections INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0,
            started_at TEXT NOT NULL, completed_at TEXT, error_message TEXT,
            source TEXT NOT NULL DEFAULT 'interactive'
        );
        CREATE TABLE scan_job_roots (
            job_id TEXT NOT NULL REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
            folder_id TEXT NOT NULL, path TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'scanning', 'scanned', 'skipped')),
            error TEXT, PRIMARY KEY(job_id, folder_id)
        );
        INSERT INTO scan_jobs (job_id, scope, state, started_at)
        VALUES ('legacy', 'quick', 'completed', '2026-10-12T08:00:00');
        INSERT INTO scan_job_roots (job_id, folder_id, path, status)
        VALUES ('legacy', 'desktop', 'C:\\Users\\alice\\Desktop', 'scanned');
        """
    )
    conn.commit()
    conn.close()

    store = ProtectionStore(db)

    assert store.get_scan_job_roots("legacy") == (("desktop", r"C:\Users\alice\Desktop"),)
    assert store.update_scan_job_root("legacy", "desktop", "partial", error="access denied")
    assert store.get_scan_job_root_coverage("legacy")[0]["status"] == "partial"


def test_enabling_schedule_requires_saved_scan_profile(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "schedule-profile.db")

    with pytest.raises(ValueError, match="profile"):
        store.set_scan_schedule(
            "S-1-5-21-1-2-3-1001",
            enabled=True,
            cadence="daily",
            local_time="21:30",
            days_of_week=(),
            now_local=datetime(2026, 10, 12, 10, 0),
        )


def test_due_scan_claim_snapshots_profile_once_and_advances_schedule(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "schedule-claim.db")
    sid = "S-1-5-21-1-2-3-1001"
    roots = (("desktop", r"C:\Users\alice\Desktop"),
             ("downloads", r"C:\Users\alice\Downloads"),
             ("startup", r"C:\Users\alice\Startup"))
    store.replace_scan_profile(sid, roots, "2026-10-12T09:00:00")
    schedule = store.set_scan_schedule(
        sid,
        enabled=True,
        cadence="daily",
        local_time="10:00",
        days_of_week=(),
        now_local=datetime(2026, 10, 12, 9, 0),
    )
    assert schedule.next_run_local == "2026-10-12T10:00"

    job = store.claim_due_scan(sid, datetime(2026, 10, 12, 10, 5), scan_active=False)

    assert job is not None and job.source == "schedule"
    assert store.get_scan_job_roots(job.job_id) == roots
    updated = store.get_scan_schedule(sid)
    assert updated is not None and updated.next_run_local == "2026-10-13T10:00"
    assert store.claim_due_scan(sid, datetime(2026, 10, 12, 10, 6), scan_active=False) is None


def test_weekly_schedule_skips_non_selected_days_and_coalesces_missed_run(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "weekly.db")
    sid = "S-1-5-21-1-2-3-1001"
    roots = (("desktop", r"C:\Users\alice\Desktop"),
             ("downloads", r"C:\Users\alice\Downloads"),
             ("startup", r"C:\Users\alice\Startup"))
    store.replace_scan_profile(sid, roots, "2026-10-12T08:00:00")
    schedule = store.set_scan_schedule(
        sid,
        enabled=True,
        cadence="weekly",
        local_time="09:00",
        days_of_week=("mon",),
        now_local=datetime(2026, 10, 12, 8, 0),
    )
    assert schedule.next_run_local == "2026-10-12T09:00"

    # Tuesday startup coalesces the missed Monday run once and schedules next Monday.
    job = store.claim_due_scan(sid, datetime(2026, 10, 13, 8, 0), scan_active=False)

    assert job is not None
    updated = store.get_scan_schedule(sid)
    assert updated is not None and updated.next_run_local == "2026-10-19T09:00"


def test_due_occurrence_is_recorded_as_skipped_when_scan_is_active(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "active-scan.db")
    sid = "S-1-5-21-1-2-3-1001"
    roots = (("desktop", r"C:\Users\alice\Desktop"),
             ("downloads", r"C:\Users\alice\Downloads"),
             ("startup", r"C:\Users\alice\Startup"))
    store.replace_scan_profile(sid, roots, "2026-10-12T09:00:00")
    store.set_scan_schedule(
        sid, enabled=True, cadence="daily", local_time="10:00", days_of_week=(),
        now_local=datetime(2026, 10, 12, 9, 0),
    )

    assert store.claim_due_scan(sid, datetime(2026, 10, 12, 10, 5), scan_active=True) is None

    schedule = store.get_scan_schedule(sid)
    assert schedule is not None and schedule.last_result == "skipped"
    assert schedule.next_run_local == "2026-10-13T10:00"


def test_service_restart_recovers_incomplete_scheduled_scan(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "recovery.db")
    sid = "S-1-5-21-1-2-3-1001"
    roots = (
        ("desktop", r"C:\Users\alice\Desktop"),
        ("downloads", r"C:\Users\alice\Downloads"),
        ("startup", r"C:\Users\alice\Startup"),
    )
    store.replace_scan_profile(sid, roots, "2026-10-12T09:00:00")
    store.set_scan_schedule(
        sid,
        enabled=True,
        cadence="daily",
        local_time="10:00",
        days_of_week=(),
        now_local=datetime(2026, 10, 12, 9, 0),
    )
    job = store.claim_due_scan(sid, datetime(2026, 10, 12, 10, 5), scan_active=False)
    assert job is not None
    store.update_scan_job(job.job_id, state="running")
    store.update_scan_job_root(job.job_id, "desktop", "scanning")
    store.update_scan_job_root(job.job_id, "downloads", "covered")

    recovered = store.recover_interrupted_scan_jobs()

    assert recovered == (job.job_id,)
    assert store.get_scan_job(job.job_id).state == "failed"
    assert store.get_scan_schedule(sid).last_result == "failed"
    coverage = {item["folder_id"]: item["status"] for item in store.get_scan_job_root_coverage(job.job_id)}
    assert coverage == {"desktop": "partial", "downloads": "partial", "startup": "skipped"}


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
