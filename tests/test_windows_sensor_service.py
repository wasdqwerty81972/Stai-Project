import json
import os
import re
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cyber_os.engine import CyberOSEngine, ThreatAlert
from cyber_os.sensors.windows_sensor_service import (
    CAPABILITIES,
    RawWindowsEvent,
    WindowsEventLogSource,
    WindowsSensorService,
    normalize_windows_event,
    parse_windows_event,
)
from ui.event_bus import event_bus


class FakeWindowsEventSource:
    def __init__(self, events=()):
        self.events = list(events)
        self.channel_status = {}
        self.closed = False
        self.opened = threading.Event()
        self._lock = threading.Lock()
        self._save_checkpoint = None
        self.checkpoints = {}

    def set_checkpoint_callbacks(self, _load_checkpoint, save_checkpoint):
        self._save_checkpoint = save_checkpoint

    def open(self):
        self.channel_status = {
            channel: {"state": "available", "error": ""}
            for channel in (
                "Security",
                "System",
                "Microsoft-Windows-DNS-Client/Operational",
                "Microsoft-Windows-Windows Defender/Operational",
            )
        }
        self.opened.set()

    def read_events(self, limit=128):
        with self._lock:
            cursor = self.checkpoints.get("Security", 0)
            return [event for event in self.events if event.record_id > cursor][:limit]

    def append(self, event):
        with self._lock:
            self.events.append(event)

    def commit_checkpoint(self, channel, record_id):
        self.checkpoints[channel] = record_id
        if self._save_checkpoint:
            self._save_checkpoint(channel, record_id)

    def close(self):
        self.closed = True


class WindowsSensorServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def _path(self, name="queue.sqlite3"):
        return str(Path(self.temp.name) / name)

    def _process_event(self, record_id=8):
        return RawWindowsEvent(
            channel="Security",
            record_id=record_id,
            windows_event_id=4688,
            timestamp="2026-10-09T10:11:12.000Z",
            fields={
                "NewProcessName": r"C:\Windows\System32\cmd.exe",
                "NewProcessId": "0x24",
                "ProcessId": "0x18",
                "ParentProcessName": r"C:\Windows\explorer.exe",
                "CommandLine": "cmd.exe /c private-secret",
            },
        )

    def test_normalizer_emits_one_privacy_filtered_event_with_both_capabilities(self):
        event = normalize_windows_event(self._process_event())
        self.assertIsNotNone(event)
        self.assertEqual(event.capabilities, ["Process Creation", "Parent-Child Process"])
        self.assertEqual(event.process, "cmd.exe")
        self.assertEqual(event.pid, 36)
        self.assertEqual(event.parent_pid, 24)
        self.assertEqual(event.sensor_ids, [1, 3])
        self.assertNotIn("cmdline", event.details)
        self.assertNotIn("CommandLine", event.details)
        self.assertEqual(len(CAPABILITIES), 14)
        self.assertEqual((CAPABILITIES[0].id, CAPABILITIES[0].key, CAPABILITIES[0].name), (1, "process_creation", "Process Creation"))

    def test_each_registered_windows_capability_executes_to_its_catalog_id(self):
        cases = (
            ("Security", 4688, {"NewProcessName": r"C:\Windows\cmd.exe", "NewProcessId": "0x24", "ProcessId": "0x18"}, [1, 3]),
            ("Security", 4656, {"ObjectType": "Process", "ProcessId": "0x24"}, [17]),
            ("Security", 4663, {"ObjectType": "File", "AccessMask": "0x2", "ObjectName": r"C:\temp\x.exe"}, [49, 50]),
            ("Security", 4660, {"ProcessId": "0x24", "HandleId": "0x1"}, [51]),
            ("Security", 4657, {"ObjectName": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "ObjectValueName": "Updater"}, [65]),
            ("Security", 4698, {"TaskName": "\\Updater"}, [67]),
            ("Security", 4697, {"ServiceName": "Example"}, [68]),
            ("System", 7045, {"ServiceName": "Example"}, [68]),
            ("Microsoft-Windows-DNS-Client/Operational", 3008, {"QueryName": "example.test"}, [89]),
            ("Security", 5156, {"Direction": "%%14593", "DestAddress": "192.0.2.1", "DestPort": "443"}, [97]),
            ("Security", 4624, {"TargetUserName": "analyst", "LogonType": "2"}, [129]),
            ("Security", 4625, {"TargetUserName": "analyst", "IpAddress": "192.0.2.1"}, [130]),
            ("Microsoft-Windows-Windows Defender/Operational", 5007, {"param1": "setting"}, [180]),
            ("System", 7036, {"param1": "Microsoft Defender Antivirus Service"}, [180]),
        )

        emitted_ids = set()
        for record_id, (channel, windows_event_id, fields, expected_ids) in enumerate(cases, 1):
            event = normalize_windows_event(RawWindowsEvent(channel, record_id, windows_event_id, "2026-10-09T10:11:12Z", fields))
            self.assertIsNotNone(event, f"event {windows_event_id} on {channel} was not recognized")
            self.assertEqual(event.sensor_ids, expected_ids, f"event {windows_event_id} on {channel}")
            emitted_ids.update(event.sensor_ids)

        self.assertEqual(emitted_ids, {capability.registry_id for capability in CAPABILITIES})

    def test_queue_is_durable_deduplicated_and_bounded(self):
        event = normalize_windows_event(self._process_event())
        service = WindowsSensorService(database_path=self._path(), queue_capacity=1)
        self.assertTrue(service._enqueue(event))
        self.assertFalse(service._enqueue(event))
        other = normalize_windows_event(self._process_event(record_id=9))
        self.assertFalse(service._enqueue(other))
        status = service.get_status()
        self.assertEqual(status["queue"], {"depth": 1, "capacity": 1, "dropped": 0, "deduplicated": 1, "backpressure": 1})

        received = []
        restarted = WindowsSensorService(callback=received.append, database_path=self._path(), queue_capacity=1)
        self.assertEqual(restarted.drain_pending(), 1)
        self.assertEqual([item.event_id for item in received], [event.event_id])
        self.assertEqual(restarted.get_status()["queue"]["depth"], 0)

    def test_start_stop_and_callback_are_idempotent(self):
        delivered = []
        delivered_event = threading.Event()

        def callback(event):
            delivered.append(event)
            delivered_event.set()

        source = FakeWindowsEventSource([self._process_event()])
        service = WindowsSensorService(
            callback=callback,
            database_path=self._path(),
            source_factory=lambda: source,
            poll_interval=0.05,
        )
        self.assertTrue(service.start())
        self.assertFalse(service.start())
        self.assertTrue(delivered_event.wait(2.0))
        self.assertEqual(len(delivered), 1)
        deadline = time.monotonic() + 2.0
        while service.get_status()["queue"]["depth"] and time.monotonic() < deadline:
            threading.Event().wait(0.01)
        self.assertEqual(service.get_status()["queue"]["depth"], 0)
        status = service.get_status()
        json.dumps(status)
        process_status = next(item for item in status["capabilities"] if item["id"] == 1)
        self.assertEqual(process_status["key"], "process_creation")
        self.assertIsInstance(process_status["permissions"], list)
        self.assertTrue(service.stop())
        self.assertTrue(service.stop())
        self.assertTrue(source.closed)

    def test_event_arriving_after_start_is_collected_and_checkpointed(self):
        delivered = []
        delivered_event = threading.Event()
        source = FakeWindowsEventSource()

        def callback(event):
            delivered.append(event)
            delivered_event.set()

        service = WindowsSensorService(
            callback=callback,
            database_path=self._path("future-event.sqlite3"),
            source_factory=lambda: source,
            poll_interval=0.05,
        )
        service.start()
        try:
            self.assertTrue(source.opened.wait(1.0))
            source.append(self._process_event(record_id=19))
            self.assertTrue(delivered_event.wait(2.0))
            self.assertEqual(
                [item.event_id for item in delivered],
                ["winlog:Security:19:2026-10-09T10:11:12.000Z"],
            )
            self.assertEqual(source.checkpoints["Security"], 19)
        finally:
            service.stop()

    def test_queue_backpressure_does_not_advance_past_unqueued_source_event(self):
        received = []
        delivered = threading.Event()

        class BurstSource(FakeWindowsEventSource):
            def read_events(self, limit=128):
                # Simulate a source batch arriving after available queue
                # capacity was calculated, so the second event must retry.
                with self._lock:
                    cursor = self.checkpoints.get("Security", 0)
                    return [event for event in self.events if event.record_id > cursor]

        source = BurstSource([self._process_event(record_id=31), self._process_event(record_id=32)])
        service = WindowsSensorService(
            database_path=self._path("backpressure.sqlite3"),
            source_factory=lambda: source,
            queue_capacity=1,
            poll_interval=0.05,
        )
        self.assertTrue(service.start())
        try:
            deadline = time.monotonic() + 2.0
            while source.checkpoints.get("Security") != 31 and time.monotonic() < deadline:
                threading.Event().wait(0.01)
            self.assertEqual(source.checkpoints.get("Security"), 31)
            self.assertEqual(service.get_status()["queue"]["depth"], 1)
            deadline = time.monotonic() + 2.0
            while service.get_status()["queue"]["backpressure"] < 1 and time.monotonic() < deadline:
                threading.Event().wait(0.01)
            self.assertGreaterEqual(service.get_status()["queue"]["backpressure"], 1)

            service.callback = lambda event: (received.append(event), delivered.set())
            self.assertTrue(delivered.wait(2.0))
            deadline = time.monotonic() + 2.0
            while source.checkpoints.get("Security") != 32 and time.monotonic() < deadline:
                threading.Event().wait(0.01)
            self.assertEqual(source.checkpoints.get("Security"), 32)
            deadline = time.monotonic() + 2.0
            while len(received) < 2 and time.monotonic() < deadline:
                threading.Event().wait(0.01)
            self.assertEqual({event.details["record_id"] for event in received}, {31, 32})
            self.assertEqual(service.get_status()["queue"]["dropped"], 0)
        finally:
            service.stop()

    def test_event_log_source_queries_new_records_and_recovers_after_log_clear(self):
        class Record:
            def __init__(self, xml):
                self.xml = xml

        class Query:
            def __init__(self, channel, flags, expression):
                self.channel = channel
                self.flags = flags
                self.expression = expression

        class FakeEventLogApi:
            EvtQueryChannelPath = 1
            EvtQueryReverseDirection = 2
            EvtQueryForwardDirection = 4
            EvtRenderEventXml = 1

            def __init__(self):
                self.events = {"Security": [self._xml(7, 4688)]}
                self.query_calls = []

            @staticmethod
            def _xml(record_id, event_id):
                return (
                    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                    "<System><Provider Name='Test'/><EventID>{}</EventID>"
                    "<Channel>Security</Channel><EventRecordID>{}</EventRecordID>"
                    "<TimeCreated SystemTime='2026-10-09T10:11:12.000Z'/></System>"
                    "</Event>"
                ).format(event_id, record_id)

            def EvtQuery(self, channel, flags, expression):
                self.query_calls.append((channel, flags, expression))
                return Query(channel, flags, expression)

            def EvtNext(self, query, limit, timeout, flags):
                events = list(self.events.get(query.channel, []))
                record_match = re.search(r"EventRecordID\s*>\s*(\d+)", query.expression)
                event_ids = {int(value) for value in re.findall(r"EventID=(\d+)", query.expression)}
                if record_match:
                    cursor = int(record_match.group(1))
                    events = [xml for xml in events if parse_windows_event(xml).record_id > cursor]
                if event_ids:
                    events = [xml for xml in events if parse_windows_event(xml).windows_event_id in event_ids]
                if query.flags & self.EvtQueryReverseDirection:
                    events.reverse()
                return [Record(xml) for xml in events[:limit]]

            @staticmethod
            def EvtRender(record, flags):
                return record.xml

            @staticmethod
            def EvtClose(handle):
                return None

        api = FakeEventLogApi()
        checkpoints = {}
        source = WindowsEventLogSource(channels=["Security"])
        source.set_checkpoint_callbacks(checkpoints.get, lambda channel, value: checkpoints.__setitem__(channel, value))
        with patch.object(WindowsEventLogSource, "_win32evtlog", return_value=api):
            source.open()
            self.assertEqual(source._last_record_id["Security"], 7)

            # An unrelated record advances the durable cursor without being emitted.
            api.events["Security"].append(api._xml(8, 9999))
            self.assertEqual(source.read_events(limit=4), [])
            self.assertEqual(source._last_record_id["Security"], 8, f"status={source.channel_status}; queries={api.query_calls}")
            self.assertEqual(checkpoints["Security"], 8, f"status={source.channel_status}; queries={api.query_calls}")

            api.events["Security"].append(api._xml(9, 4688))
            events = source.read_events(limit=4)
            self.assertEqual([event.record_id for event in events], [9])
            source.commit_checkpoint("Security", 9)

            # Clearing the log resets record IDs and must reset the cursor too.
            api.events["Security"] = [api._xml(1, 9999), api._xml(2, 4688)]
            self.assertEqual(source.read_events(limit=4), [])
            self.assertEqual(source._last_record_id["Security"], 2)
            api.events["Security"].append(api._xml(3, 4688))
            self.assertEqual([event.record_id for event in source.read_events(limit=4)], [3])

    def test_event_log_source_reports_why_runtime_api_is_unavailable(self):
        source = WindowsEventLogSource(channels=["Security"])
        with patch.object(WindowsEventLogSource, "_win32evtlog", side_effect=RuntimeError("pywin32 is not installed; Windows event source unavailable")):
            source.open()

        self.assertEqual(source.channel_status["Security"]["state"], "unsupported")
        self.assertEqual(source.channel_status["Security"]["error"], "pywin32 is not installed; Windows event source unavailable")


class CyberOSEngineSensorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp.name)

    def tearDown(self):
        os.chdir(self.original_cwd)
        self.temp.cleanup()

    def test_sensor_callback_emits_canonical_event_once_and_response_waits_for_approval(self):
        engine = CyberOSEngine(config_path="missing-config.json")
        engine.running = True
        event = normalize_windows_event(
            RawWindowsEvent(
                "Security", 41, 4688, "2026-10-09T10:11:12Z",
                {"NewProcessName": r"C:\Windows\cmd.exe", "NewProcessId": "0x24", "ProcessId": "0x18"},
            )
        )
        before = len(event_bus.get_history("telemetry_event"))
        engine._handle_sensor_event(event)
        engine._handle_sensor_event(event)
        self.assertEqual(len(event_bus.get_history("telemetry_event")), before + 1)

        alert = ThreatAlert(
            timestamp="2026-10-09T10:11:12Z",
            alert_type="suspicious_network_activity",
            severity="HIGH",
            mitre_technique="T1046",
            technique_name="Network Service Scanning",
            summary="Source IP 203.0.113.5 is suspicious",
            evidence=["test"],
            ai_reasoning="test",
            blast_radius="test",
            threat_score=8,
            recommended_actions=["Block source IP"],
            event_id="alert-1",
        )
        attempts = []
        engine._block_ip = lambda ip, *, approved=False: attempts.append((ip, approved)) or approved
        before_approvals = len(event_bus.get_history("response_approval_required"))
        self.assertEqual(engine._execute_response(alert), [])
        self.assertEqual(attempts, [])
        new_requests = event_bus.get_history("response_approval_required")[before_approvals:]
        approval_event = new_requests[-1]
        approval_id = approval_event.data["approval_id"]
        self.assertEqual(approval_event.data["request_id"], approval_id)
        self.assertEqual(approval_event.data["tool"], "cyberos_containment")
        self.assertEqual(approval_event.data["arguments"]["proposed_actions"], ["Block source IP"])
        self.assertTrue(engine.has_pending_response_approval(approval_id))
        self.assertEqual(engine.resolve_response_approval(approval_id, True, approved_by="analyst"), ["Blocked IP: 203.0.113.5"])
        self.assertFalse(engine.has_pending_response_approval(approval_id))
        self.assertEqual(attempts, [("203.0.113.5", True)])

    def test_failed_logon_detection_uses_utc_window_boundaries(self):
        engine = CyberOSEngine(config_path="missing-config.json")
        now = datetime.now(timezone.utc)
        recent = [
            normalize_windows_event(
                RawWindowsEvent(
                    "Security",
                    record_id,
                    4625,
                    (now - timedelta(seconds=record_id)).isoformat(),
                    {"TargetUserName": "analyst", "IpAddress": "203.0.113.5"},
                )
            )
            for record_id in range(1, 6)
        ]
        engine.events.extend(recent)
        self.assertIsNotNone(engine._check_brute_force(recent[-1]))

        engine.events.clear()
        stale = [
            normalize_windows_event(
                RawWindowsEvent(
                    "Security",
                    record_id + 10,
                    4625,
                    (now - timedelta(seconds=120 + record_id)).isoformat(),
                    {"TargetUserName": "analyst", "IpAddress": "203.0.113.5"},
                )
            )
            for record_id in range(1, 6)
        ]
        engine.events.extend(stale)
        self.assertIsNone(engine._check_brute_force(stale[-1]))


if __name__ == "__main__":
    unittest.main()
