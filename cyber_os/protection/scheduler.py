"""Low-frequency scheduler for the enrolled user's Quick Scan schedule."""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Any, Callable


LOGGER = logging.getLogger(__name__)


class ProtectionScheduler:
    """Check durable schedule state without enumerating files while idle."""

    def __init__(
        self,
        service: Any,
        owner_sid: str,
        *,
        interval_seconds: float = 60.0,
        clock: Callable[[], datetime] = datetime.now,
    ) -> None:
        if not owner_sid:
            raise ValueError("an enrolled dashboard SID is required")
        self._service = service
        self._owner_sid = owner_sid
        self._interval_seconds = max(0.01, float(interval_seconds))
        self._clock = clock
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="stai-protection-scheduler",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._service.run_due_scheduled_scan(
                    self._owner_sid,
                    now_local=self._clock(),
                )
            except Exception:
                LOGGER.exception("scheduled protection scan check failed")
            if self._stop_event.wait(self._interval_seconds):
                return
