"""
tests/test_audit_logger.py — the forensic trail must not lose records.

AuditLogger used to parse the whole JSON array, append, and rewrite the file on
every event. That made writes O(n) each and the session O(n^2), and because no
lock was held, two concurrent investigations interleaved read-modify-write and
dropped each other's records — observed live as
"[!] Audit log write error: [Errno 13] Permission denied". A JSONDecodeError
was handled with ``logs = []``, so a single corrupt byte silently discarded the
entire history the class exists to preserve, and the bare ``except Exception:
print(...)`` meant a log that had stopped recording looked exactly like a quiet
one.

These tests pin the properties that make the trail trustworthy: nothing is lost
under concurrency, damage is contained to the damaged record, and a failed
write is visible to the caller rather than only on stdout.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cyber_tools import AuditLogger  # noqa: E402


class AuditLoggerBasicsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = os.path.join(self._dir.name, "audit.jsonl")

    def test_constructing_a_logger_creates_no_file(self) -> None:
        # Append mode creates the file on first use, so building a registry
        # cannot fail merely because the working directory is not writable.
        AuditLogger(self.path)
        self.assertFalse(os.path.exists(self.path))

    def test_a_missing_parent_directory_is_created(self) -> None:
        nested = os.path.join(self._dir.name, "a", "b", "audit.jsonl")
        log = AuditLogger(nested)
        self.assertTrue(log.log_event("probe", {}))
        self.assertEqual(len(log.read_events()), 1)

    def test_log_event_reports_whether_it_reached_disk(self) -> None:
        log = AuditLogger(self.path)
        self.assertIs(log.log_event("probe", {"a": 1}), True)

    def test_an_event_round_trips(self) -> None:
        log = AuditLogger(self.path)
        log.log_event("nmap_scan", {"target": "10.0.0.1"}, status="DENIED")
        (event,) = log.read_events()
        self.assertEqual(event["action"], "nmap_scan")
        self.assertEqual(event["status"], "DENIED")
        self.assertEqual(event["details"]["target"], "10.0.0.1")
        self.assertIn("timestamp", event)

    def test_reading_a_log_that_was_never_written_is_not_an_error(self) -> None:
        self.assertEqual(AuditLogger(self.path).read_events(), [])

    def test_an_unserializable_detail_does_not_cost_the_record(self) -> None:
        # Tool arguments are arbitrary. A value json cannot encode must degrade
        # to its repr, never discard the audit entry around it.
        log = AuditLogger(self.path)
        self.assertTrue(log.log_event("exotic", {"obj": object(), "set": {1, 2}}))
        (event,) = log.read_events()
        self.assertEqual(event["action"], "exotic")

    def test_suppress_stops_writes_and_says_so(self) -> None:
        log = AuditLogger(self.path)
        log.suppress(True)
        self.assertIs(log.log_event("registration_noise", {}), False)
        log.suppress(False)
        self.assertIs(log.log_event("real_event", {}), True)
        self.assertEqual([e["action"] for e in log.read_events()], ["real_event"])

    def test_limit_returns_the_most_recent_events_oldest_first(self) -> None:
        log = AuditLogger(self.path)
        for n in range(10):
            log.log_event(f"event_{n}", {})
        recent = log.read_events(limit=3)
        self.assertEqual([e["action"] for e in recent], ["event_7", "event_8", "event_9"])


class AuditLoggerDurabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = os.path.join(self._dir.name, "audit.jsonl")

    def test_a_corrupt_line_costs_one_event_not_the_history(self) -> None:
        log = AuditLogger(self.path)
        for n in range(5):
            log.log_event(f"before_{n}", {})
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write("{this is not json\n")
        log.log_event("after", {})

        actions = [e["action"] for e in log.read_events()]
        self.assertEqual(actions, ["before_0", "before_1", "before_2",
                                   "before_3", "before_4", "after"])

    def test_a_truncated_final_line_does_not_hide_earlier_events(self) -> None:
        # A process killed mid-write leaves a partial line. Everything before it
        # is still valid evidence.
        log = AuditLogger(self.path)
        log.log_event("recorded", {})
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write('{"action": "half_writ')
        self.assertEqual([e["action"] for e in log.read_events()], ["recorded"])

    def test_a_legacy_json_array_log_is_still_readable(self) -> None:
        # The format changed from a JSON array to JSONL; history written before
        # the change must not be orphaned.
        legacy = os.path.join(self._dir.name, "audit_log.json")
        with open(legacy, "w", encoding="utf-8") as handle:
            json.dump(
                [{"action": "old_event", "status": "SUCCESS"},
                 {"action": "newer_event", "status": "DENIED"}],
                handle,
            )
        events = AuditLogger(legacy).read_events()
        self.assertEqual([e["action"] for e in events], ["old_event", "newer_event"])

    def test_a_failed_write_is_counted_and_surfaced(self) -> None:
        # The old code printed and returned, so a log that had stopped
        # recording was indistinguishable from a log with nothing to record.
        log = AuditLogger(self.path)
        reported: list = []
        log._on_error = reported.append
        log.log_path = os.path.join(self.path, "unwritable", "audit.jsonl")

        self.assertIs(log.log_event("doomed", {}), False)
        health = log.health()
        self.assertEqual(health["dropped_events"], 1)
        self.assertFalse(health["complete"])
        self.assertIsNotNone(health["last_error"])
        self.assertEqual(len(reported), 1)

    def test_health_reports_a_complete_trail_when_nothing_was_dropped(self) -> None:
        log = AuditLogger(self.path)
        log.log_event("probe", {})
        health = log.health()
        self.assertTrue(health["complete"])
        self.assertEqual(health["dropped_events"], 0)
        self.assertIsNone(health["last_error"])
        self.assertEqual(health["log_path"], os.path.abspath(self.path))


class AuditLoggerConcurrencyTests(unittest.TestCase):
    """The regression that motivated the rewrite. AgentRuntime is a singleton
    per CyberAgent running overlapping investigations, and the GUI runs in its
    own process, so both of these are real deployment shapes."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.path = os.path.join(self._dir.name, "audit.jsonl")

    def test_concurrent_threads_lose_no_events(self) -> None:
        log = AuditLogger(self.path)
        threads_count, per_thread = 12, 50

        def writer(index: int) -> None:
            for n in range(per_thread):
                log.log_event("tool_execution", {"thread": index, "n": n})

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(threads_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        events = log.read_events()
        self.assertEqual(log.dropped_events, 0)
        self.assertEqual(len(events), threads_count * per_thread)
        # Every (thread, n) pair exactly once: interleaved rewrites used to
        # clobber whole ranges, which a bare count could still have matched.
        pairs = {(e["details"]["thread"], e["details"]["n"]) for e in events}
        self.assertEqual(len(pairs), threads_count * per_thread)

    def test_concurrent_processes_lose_no_events(self) -> None:
        child = (
            "import sys\n"
            f"sys.path.insert(0, {str(REPO_ROOT)!r})\n"
            "from cyber_tools import AuditLogger\n"
            "log = AuditLogger(sys.argv[1])\n"
            "for n in range(60):\n"
            "    log.log_event('mp', {'pid': sys.argv[2], 'n': n})\n"
            "print(log.dropped_events)\n"
        )
        script = os.path.join(self._dir.name, "child.py")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write(child)

        procs = [
            subprocess.Popen(
                [sys.executable, script, self.path, str(i)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            for i in range(5)
        ]
        drops = []
        for proc in procs:
            out, err = proc.communicate(timeout=120)
            self.assertEqual(proc.returncode, 0, err)
            drops.append(int(out.strip()))

        self.assertEqual(sum(drops), 0, "a child process dropped an audit event")
        events = AuditLogger(self.path).read_events()
        self.assertEqual(len(events), 5 * 60)
        pairs = {(e["details"]["pid"], e["details"]["n"]) for e in events}
        self.assertEqual(len(pairs), 5 * 60)

    def test_every_line_remains_independently_parseable(self) -> None:
        # Interleaved writes used to produce a file that no longer parsed at
        # all. Line-orientation is what contains the damage, so assert it.
        log = AuditLogger(self.path)

        def writer(index: int) -> None:
            for n in range(40):
                log.log_event("tool_execution", {"thread": index, "padding": "x" * 200})

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        with open(self.path, "r", encoding="utf-8") as handle:
            lines = [line for line in handle.read().splitlines() if line.strip()]
        self.assertEqual(len(lines), 8 * 40)
        for line in lines:
            json.loads(line)  # raises if a write was torn


if __name__ == "__main__":
    unittest.main()
