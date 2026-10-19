"""Harmless, real Windows process-monitor smoke test (no driver/service install)."""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from ui.process_monitor import ProcessRegistry


pytestmark = pytest.mark.skipif(os.name != "nt", reason="requires Windows process APIs")


def _wait_for(predicate, timeout: float = 8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    return None


def test_live_child_process_appears_samples_and_disappears():
    registry = ProcessRegistry(sample_interval=0.25, reconcile_interval=0.25)
    child = None
    registry.start()
    try:
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import time\n"
                "data = bytearray(24 * 1024 * 1024)\n"
                "end = time.monotonic() + 30\n"
                "while time.monotonic() < end:\n"
                "    sum(range(12000))\n"
                "    time.sleep(0.001)\n",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        child_pid = child.pid

        def find_child():
            return next((row for row in registry.snapshot()["processes"] if row["pid"] == child_pid), None)

        appearing = _wait_for(find_child)
        assert appearing is not None, "new Windows process did not appear in the live registry"
        assert appearing["identity_verified"] is True

        def find_sampled_child():
            row = find_child()
            return row if row and row.get("cpu_percent") is not None and row.get("memory_bytes") is not None else None

        sampled = _wait_for(find_sampled_child, timeout=25.0)
        assert sampled is not None, f"process CPU/RAM sample was not produced: {registry.health()}"
        assert sampled["memory_bytes"] >= 16 * 1024 * 1024

        child.kill()
        child.wait(timeout=8)
        disappeared = _wait_for(lambda: True if find_child() is None else None)
        assert disappeared is not None, "exited process remained in the running registry"
        assert registry.health()["state"] == "running"
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        registry.stop()
