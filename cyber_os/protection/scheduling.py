"""Persisted local-time scan schedules for the Windows protection service."""

from __future__ import annotations

import re
import threading
from datetime import datetime, timedelta
from typing import Any, Literal

from .store import ProtectionStore


_LOCAL_TIME = re.compile(r"(?:[01]\d|2[0-3]):[0-5]\d\Z")
_TERMINAL_STATES = {"completed", "partial", "cancelled", "failed"}


def next_scan_time(
    now: datetime,
    frequency: Literal["daily", "weekly"],
    local_time: str,
    weekday: int | None,
) -> str:
    """Return the next local wall-clock occurrence as an offset ISO timestamp."""
    if not _LOCAL_TIME.fullmatch(local_time):
        raise ValueError("local_time must use HH:MM")
    hour, minute = (int(value) for value in local_time.split(":"))
    local_now = now if now.tzinfo is not None else now.astimezone()
    candidate = local_now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if frequency == "daily":
        if candidate <= local_now:
            candidate += timedelta(days=1)
    elif frequency == "weekly":
        if weekday is None or type(weekday) is not int or not 0 <= weekday <= 6:
            raise ValueError("weekly schedules require a weekday from 0 through 6")
        candidate += timedelta(days=(weekday - local_now.weekday()) % 7)
        if candidate <= local_now:
            candidate += timedelta(days=7)
    else:
        raise ValueError("frequency must be daily or weekly")
    return candidate.isoformat(timespec="seconds")


class ScanScheduleManager:
    """Configure and run one durable daily or weekly scan schedule."""

    def __init__(
        self,
        store: ProtectionStore,
        service: Any,
        *,
        poll_seconds: float = 15.0,
    ) -> None:
        self.store = store
        self.service = service
        self._poll_seconds = max(1.0, poll_seconds)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def get_schedule(self) -> dict[str, Any]:
        self._refresh_last_result()
        return self.store.get_scan_schedule()

    def configure(
        self,
        *,
        enabled: bool,
        frequency: str,
        scope: str,
        local_time: str,
        weekday: int | None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if type(enabled) is not bool:
            raise ValueError("enabled must be a boolean")
        if frequency not in ("daily", "weekly"):
            raise ValueError("frequency must be daily or weekly")
        if scope not in ("quick", "system"):
            raise ValueError("scope must be quick or system")
        if not _LOCAL_TIME.fullmatch(local_time):
            raise ValueError("local_time must use HH:MM")
        if frequency == "weekly":
            if type(weekday) is not int or not 0 <= weekday <= 6:
                raise ValueError("weekly schedules require a weekday from 0 through 6")
        elif weekday is not None:
            raise ValueError("daily schedules do not accept a weekday")
        at = next_scan_time(now or datetime.now().astimezone(), frequency, local_time, weekday)
        with self._lock:
            return self.store.save_scan_schedule(
                enabled=enabled,
                frequency=frequency,
                scope=scope,
                local_time=local_time,
                weekday=weekday,
                next_run_at=at if enabled else None,
            )

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="stai-protection-scan-scheduler",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=max(0.0, timeout))

    def _run(self) -> None:
        self.run_due()
        while not self._stop_event.wait(self._poll_seconds):
            self.run_due()

    def run_due(self, *, now: datetime | None = None) -> dict[str, Any]:
        """Run one due scan; safe to call repeatedly from the scheduler loop."""
        current = (now or datetime.now().astimezone()).astimezone()
        self._refresh_last_result()
        with self._lock:
            schedule = self.store.get_scan_schedule()
            next_at = schedule.get("next_run_at")
            if not schedule["enabled"] or not next_at:
                return schedule
            due_at = datetime.fromisoformat(next_at)
            if due_at.tzinfo is None:
                due_at = due_at.astimezone()
            if due_at > current:
                return schedule

            following = next_scan_time(
                current,
                schedule["frequency"],
                schedule["local_time"],
                schedule["weekday"],
            )
            try:
                job = self.service.start_scan(schedule["scope"])
            except RuntimeError as exc:
                busy = "already in progress" in str(exc).casefold()
                self.store.update_scan_schedule_run(
                    next_run_at=following,
                    last_run_at=due_at.isoformat(timespec="seconds"),
                    last_job_id=None,
                    last_result="skipped_busy" if busy else "failed",
                    error_message="A scan was already running at the scheduled time." if busy else str(exc),
                )
            except Exception as exc:
                self.store.update_scan_schedule_run(
                    next_run_at=following,
                    last_run_at=due_at.isoformat(timespec="seconds"),
                    last_job_id=None,
                    last_result="unavailable",
                    error_message="The scheduled scan could not start.",
                )
            else:
                self.store.update_scan_schedule_run(
                    next_run_at=following,
                    last_run_at=due_at.isoformat(timespec="seconds"),
                    last_job_id=job.job_id,
                    last_result="running",
                    error_message=None,
                )
            return self.store.get_scan_schedule()

    def _refresh_last_result(self) -> None:
        schedule = self.store.get_scan_schedule()
        if schedule.get("last_result") != "running" or not schedule.get("last_job_id"):
            return
        job = self.store.get_scan_job(schedule["last_job_id"])
        if job is None or job.state not in _TERMINAL_STATES:
            return
        result = job.state
        if job.state == "completed" and (job.errors or job.unknown_verdicts or job.files_skipped):
            result = "completed_with_gaps"
        self.store.update_scan_schedule_run(
            next_run_at=schedule["next_run_at"],
            last_run_at=schedule["last_run_at"],
            last_job_id=schedule["last_job_id"],
            last_result=result,
            error_message=job.error_message,
        )
