from __future__ import annotations

import asyncio
import gc
import warnings

from ui import api_server
from ui.event_bus import AgentEvent


def test_event_after_api_loop_closes_does_not_leak_broadcast_coroutine(monkeypatch):
    closed_loop = asyncio.new_event_loop()
    closed_loop.close()
    monkeypatch.setattr(api_server, "_main_loop", closed_loop)
    monkeypatch.setattr(api_server, "_save_history", lambda: None)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", RuntimeWarning)
        api_server._on_event(AgentEvent(type="shutdown_race"))
        gc.collect()

    leaked_coroutines = [
        warning for warning in caught
        if "coroutine '_broadcast' was never awaited" in str(warning.message)
    ]
    assert not leaked_coroutines


def test_loop_close_race_closes_coroutine_and_clears_stale_loop(monkeypatch):
    class RacingLoop:
        closed = False

        def is_closed(self):
            return self.closed

        def is_running(self):
            return True

    loop = RacingLoop()
    scheduled = []

    def close_during_schedule(coroutine, target_loop):
        assert target_loop is loop
        scheduled.append(coroutine)
        loop.closed = True
        raise RuntimeError("Event loop is closed")

    monkeypatch.setattr(api_server, "_main_loop", loop)
    monkeypatch.setattr(asyncio, "run_coroutine_threadsafe", close_during_schedule)

    assert not api_server._schedule_broadcast({"type": "race"}, loop)
    assert len(scheduled) == 1
    assert scheduled[0].cr_frame is None
    assert api_server._main_loop is None
