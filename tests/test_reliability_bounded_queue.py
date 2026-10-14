"""Reliability: the scan request path must stay bounded AND must still stop.

Agent 7 (QA/Reliability) baseline guard. The user-mode client receives file I/O
scan requests from the minifilter faster than it can scan them whenever the disk
is busy (an archive extraction, an installer, a build). If the hand-off queue
between the receive pump and the scan loop is unbounded, a burst of I/O turns
into unbounded service-side memory growth -- the classic way an endpoint agent
takes a machine down instead of protecting it.

`FilterClient.run_until_stopped` allocates `queue.Queue(maxsize=32)` to mirror
the driver's own 32-request cap and uses a blocking `put`, so saturation applies
backpressure rather than buffering. These tests pin the bound, and they pin the
other half of the contract that the bound creates a duty to honour: a saturated
loop must still shut down when asked.

IMPORTANT -- every test here runs the loop on a daemon thread behind an explicit
deadline. pytest-timeout is NOT installed in this environment, so a loop that
fails to return would otherwise hang the entire suite instead of reporting a
failure. The deadline turns a hang into a readable assertion.

Scope note: the native transport is an in-memory stand-in. This is NOT kernel or
driver integration coverage and must never be reported as such.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
from typing import Any, List, Optional

import pytest


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_os.protection.filter_client import (  # noqa: E402
    FilterClient,
    NativeFilterClient,
    NativeFilterMessage,
)
from cyber_os.protection.filter_protocol import (  # noqa: E402
    FilterRequest,
    encode_filter_request,
)
from cyber_os.protection.models import ScanVerdict  # noqa: E402


# The cap the production loop allocates (cyber_os/protection/filter_client.py).
EXPECTED_QUEUE_MAXSIZE = 32


def _allow_verdict() -> ScanVerdict:
    return ScanVerdict(
        status="unknown",
        action="allow",
        rule_id=None,
        rule_version="saturation-test",
        sha256=None,
        reason="saturation fixture",
    )


class _FloodNative(NativeFilterClient):
    """A port that hands out scan requests as fast as they are asked for.

    This is the saturation condition: the driver always has another request
    ready, so the only thing that can keep the backlog from growing is the
    bounded queue.
    """

    def __init__(self, total: int) -> None:
        self.total = total
        self._lock = threading.Lock()
        self.issued = 0
        self.replies: List[int] = []
        self.closed = False

    def connect(self, port_name: str, timeout_ms: int) -> bool:
        return True

    def receive(self, timeout_ms: int) -> Optional[NativeFilterMessage]:
        with self._lock:
            if self.issued >= self.total:
                return None
            self.issued += 1
            request_id = self.issued
        frame = encode_filter_request(
            FilterRequest(
                request_id=request_id,
                operation="create",
                path=rf"C:\saturation\{request_id}.bin",
            )
        )
        return NativeFilterMessage(request_id, frame, 4096)

    def send(self, data: bytes) -> bool:
        return True

    def reply(self, message_id: int, data: bytes) -> bool:
        with self._lock:
            self.replies.append(message_id)
        return True

    def close(self) -> None:
        self.closed = True


class _SlowService:
    """A scanner slow enough that the receive pump outruns it."""

    def __init__(self, delay: float = 0.004) -> None:
        self.delay = delay
        self.scanned: List[str] = []
        self._lock = threading.Lock()

    def scan_file(self, path: Any) -> ScanVerdict:
        if self.delay:
            time.sleep(self.delay)
        with self._lock:
            self.scanned.append(str(path))
        return _allow_verdict()


class _ObservedQueue(queue.Queue):
    """A Queue that records the deepest backlog it ever held."""

    peak_depth = 0
    observed_maxsize: Optional[int] = None

    def __init__(self, maxsize: int = 0) -> None:
        super().__init__(maxsize)
        type(self).observed_maxsize = maxsize

    def put(self, item: Any, block: bool = True, timeout: Optional[float] = None) -> None:
        super().put(item, block, timeout)
        depth = self.qsize()
        if depth > type(self).peak_depth:
            type(self).peak_depth = depth


@pytest.fixture
def observed_queue(monkeypatch: pytest.MonkeyPatch):
    """Swap the loop's Queue for one that reports its peak depth and its cap."""
    import cyber_os.protection.filter_client as filter_client_module

    _ObservedQueue.peak_depth = 0
    _ObservedQueue.observed_maxsize = None
    monkeypatch.setattr(filter_client_module.queue, "Queue", _ObservedQueue)
    return _ObservedQueue


class _LoopRun:
    """Result of driving run_until_stopped behind a deadline."""

    def __init__(self) -> None:
        self.returned = False
        self.processed: Optional[int] = None
        self.error: Optional[BaseException] = None
        self.elapsed_after_stop = 0.0


def _drive_loop(
    client: FilterClient,
    service: Any,
    *,
    run_for: float,
    shutdown_deadline: float,
    retry_delay_seconds: float = 1.0,
) -> _LoopRun:
    """Run the loop for `run_for` seconds, then stop it and wait, bounded.

    Never blocks forever: the loop runs on a daemon thread, so a loop that
    refuses to return is reported as `returned is False` instead of hanging
    the test session.
    """
    result = _LoopRun()
    stop_event = threading.Event()
    finished = threading.Event()

    def _run() -> None:
        try:
            result.processed = client.run_until_stopped(
                service,
                stop_event,
                retry_delay_seconds=retry_delay_seconds,
                idle_delay_seconds=0.01,
            )
        except BaseException as exc:  # pragma: no cover - surfaced by the test
            result.error = exc
        finally:
            finished.set()

    worker = threading.Thread(target=_run, name="qa7-filter-loop", daemon=True)
    worker.start()
    finished.wait(run_for)

    stop_requested = time.monotonic()
    stop_event.set()
    result.returned = finished.wait(shutdown_deadline)
    result.elapsed_after_stop = time.monotonic() - stop_requested
    return result


# ---------------------------------------------------------------------------
# The bound itself
# ---------------------------------------------------------------------------


def test_scan_request_queue_is_allocated_bounded(observed_queue) -> None:
    """The receive/scan hand-off must use a bounded queue, not an open one."""
    native = _FloodNative(total=4)
    client = FilterClient(native_client=native)
    _drive_loop(client, _SlowService(delay=0.0), run_for=0.8, shutdown_deadline=5.0)

    assert observed_queue.observed_maxsize == EXPECTED_QUEUE_MAXSIZE, (
        "the scan request hand-off queue was allocated with maxsize="
        f"{observed_queue.observed_maxsize!r}; an unbounded (maxsize=0) queue "
        "lets a disk-I/O burst grow the service's memory without limit"
    )


def test_backlog_never_exceeds_the_cap_while_the_scanner_lags(observed_queue) -> None:
    """Under saturation the backlog must stay capped, not grow with the burst."""
    native = _FloodNative(total=5_000)
    service = _SlowService(delay=0.003)
    client = FilterClient(native_client=native)

    _drive_loop(client, service, run_for=1.5, shutdown_deadline=5.0)

    # Confirm the fixture really did saturate, so the bound is under load.
    assert native.issued > len(service.scanned), (
        f"the fixture did not saturate: issued={native.issued} "
        f"scanned={len(service.scanned)}"
    )
    assert observed_queue.peak_depth <= EXPECTED_QUEUE_MAXSIZE, (
        f"scan backlog reached {observed_queue.peak_depth} entries against a "
        f"cap of {EXPECTED_QUEUE_MAXSIZE}; the bound is not holding"
    )


def test_no_scanned_request_is_left_without_a_reply() -> None:
    """Backpressure must not drop a request that was already scanned.

    A scanned request with no reply leaves the driver's pended I/O
    uncompleted, which stalls the originating application's file open.
    """
    native = _FloodNative(total=60)
    service = _SlowService(delay=0.001)
    client = FilterClient(native_client=native)

    _drive_loop(client, service, run_for=2.0, shutdown_deadline=5.0)

    assert len(native.replies) >= len(service.scanned), (
        f"{len(service.scanned)} requests were scanned but only "
        f"{len(native.replies)} replies were sent"
    )
    assert len(set(native.replies)) == len(native.replies), (
        "the same OS message was replied to more than once"
    )


# ---------------------------------------------------------------------------
# The duty the bound creates: a saturated loop must still stop
# ---------------------------------------------------------------------------


def test_saturated_loop_returns_when_its_stop_event_is_set() -> None:
    """A full queue must not wedge shutdown.

    Regression guard for a shutdown deadlock: `_receive_pump` does a blocking
    `request_queue.put(...)` on the 32-slot queue, while `run_until_stopped`
    joins the pump threads with no timeout once the drain loop has exited. If
    the pumps are parked in `put()` on a full queue when `stop_event` fires,
    nothing drains the queue, `put()` never observes the stop flag, and the
    join waits forever -- the service reports SERVICE_STOP_PENDING until the
    SCM kills the process, leaving the driver with pended I/O.
    """
    native = _FloodNative(total=10_000)
    service = _SlowService(delay=0.004)
    client = FilterClient(native_client=native)

    run = _drive_loop(client, service, run_for=1.2, shutdown_deadline=10.0)

    assert run.error is None, f"the loop raised during shutdown: {run.error!r}"
    assert run.returned, (
        "run_until_stopped did not return within 10s of its stop_event being "
        "set while the scan queue was saturated. The receive pumps are parked "
        "in a blocking queue.put() on the full 32-slot queue and the drain "
        "loop has already exited, so the untimed receiver.join() never "
        "completes. Windows service shutdown hangs until the SCM kills the "
        "process."
    )
    assert len(native.replies) == native.issued, (
        f"the receive pumps obtained {native.issued} requests, but only "
        f"{len(native.replies)} received requests were completed; shutdown "
        "must fail open any request it cannot enqueue"
    )
    assert native.closed is True, "the native port was not closed on shutdown"


def test_unsaturated_loop_shuts_down_promptly() -> None:
    """The control case: with the scanner keeping up, shutdown is clean."""
    native = _FloodNative(total=5)
    client = FilterClient(native_client=native)

    run = _drive_loop(client, _SlowService(delay=0.0), run_for=0.8, shutdown_deadline=10.0)

    assert run.error is None, f"the loop raised during shutdown: {run.error!r}"
    assert run.returned, (
        f"an idle loop failed to stop within 10s ({run.elapsed_after_stop:.1f}s)"
    )
    assert native.closed is True


def test_loop_exits_without_spinning_when_the_driver_is_absent() -> None:
    """No port means a bounded, interruptible retry -- not a busy loop."""

    class _NeverConnects(_FloodNative):
        def connect(self, port_name: str, timeout_ms: int) -> bool:
            return False

    native = _NeverConnects(total=0)
    client = FilterClient(native_client=native)

    run = _drive_loop(
        client,
        _SlowService(),
        run_for=0.4,
        shutdown_deadline=5.0,
        retry_delay_seconds=0.05,
    )

    assert run.returned, (
        "the no-driver retry loop did not honour its stop event; an absent "
        "driver must not block service shutdown"
    )
    assert run.processed == 0
    assert native.issued == 0, "requests were processed with no connected port"
