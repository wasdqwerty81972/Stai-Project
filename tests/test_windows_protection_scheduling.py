from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cyber_os.protection.scheduling import ScanScheduleManager, next_scan_time
from cyber_os.protection.store import ProtectionStore


def test_daily_schedule_selects_next_local_occurrence() -> None:
    now = datetime(2026, 10, 13, 10, 30, tzinfo=timezone.utc)

    assert next_scan_time(now, "daily", "10:30", None) == "2026-10-14T10:30:00+00:00"


def test_weekly_schedule_selects_requested_weekday() -> None:
    now = datetime(2026, 10, 13, 10, 30, tzinfo=timezone.utc)  # Tuesday

    assert next_scan_time(now, "weekly", "09:00", 4) == "2026-10-16T09:00:00+00:00"


def test_schedule_manager_persists_and_runs_due_scan_once(tmp_path) -> None:
    store = ProtectionStore(tmp_path / "schedule.db")

    class FakeService:
        def __init__(self):
            self.jobs = []

        def start_scan(self, scope):
            job = type("Job", (), {"job_id": f"job-{len(self.jobs) + 1}", "scope": scope})()
            self.jobs.append(job)
            return job

    service = FakeService()
    manager = ScanScheduleManager(store, service)
    now = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)
    configured = manager.configure(
        enabled=True,
        frequency="daily",
        scope="quick",
        local_time="10:00",
        weekday=None,
        now=now,
    )
    assert configured["enabled"] is True
    assert configured["next_run_at"] == "2026-10-14T10:00:00+00:00"

    manager.run_due(now=datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc))
    manager.run_due(now=datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc))

    saved = store.get_scan_schedule()
    assert len(service.jobs) == 1
    assert saved["last_job_id"] == "job-1"
    assert saved["last_result"] == "running"


def test_schedule_manager_records_partial_scan_outcome(tmp_path) -> None:
    store = ProtectionStore(tmp_path / "partial-schedule.db")
    store.create_scan_job("job-partial", "quick")
    store.update_scan_job("job-partial", state="partial", unknown_verdicts=2)
    manager = ScanScheduleManager(store, object())
    manager.configure(
        enabled=True,
        frequency="daily",
        scope="quick",
        local_time="10:00",
        weekday=None,
        now=datetime(2026, 10, 13, 9, 0, tzinfo=timezone.utc),
    )
    store.update_scan_schedule_run(
        next_run_at="2026-10-14T10:00:00+00:00",
        last_run_at="2026-10-13T10:00:00+00:00",
        last_job_id="job-partial",
        last_result="running",
        error_message=None,
    )

    assert manager.get_schedule()["last_result"] == "partial"


@pytest.mark.parametrize(
    "values",
    [
        {"enabled": 1, "frequency": "daily", "scope": "quick", "local_time": "03:00", "weekday": None},
        {"enabled": True, "frequency": "hourly", "scope": "quick", "local_time": "03:00", "weekday": None},
        {"enabled": True, "frequency": "weekly", "scope": "quick", "local_time": "03:00", "weekday": 7},
        {"enabled": True, "frequency": "daily", "scope": "quick", "local_time": "25:00", "weekday": None},
    ],
)
def test_schedule_rejects_invalid_configuration(tmp_path, values) -> None:
    manager = ScanScheduleManager(ProtectionStore(tmp_path / "schedule.db"), object())

    with pytest.raises(ValueError):
        manager.configure(**values)
