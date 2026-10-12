from __future__ import annotations

import threading

from cyber_os.protection.scheduler import ProtectionScheduler


def test_scheduler_checks_periodically_and_stops_promptly() -> None:
    called = threading.Event()

    class Service:
        calls = 0

        def run_due_scheduled_scan(self, owner_sid, *, now_local=None):
            assert owner_sid == "S-1-5-21-1-2-3-1001"
            self.calls += 1
            called.set()

    service = Service()
    scheduler = ProtectionScheduler(service, "S-1-5-21-1-2-3-1001", interval_seconds=0.01)

    scheduler.start()
    assert called.wait(timeout=1)
    scheduler.stop()

    assert service.calls >= 1
    assert not scheduler.running
