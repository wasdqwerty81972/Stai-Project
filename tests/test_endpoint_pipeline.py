import os
import tempfile
import unittest
from pathlib import Path

from cyber_os.engine import CyberOSEngine, EventType, SecurityEvent
from cyber_os.incident_manager import IncidentManager
from ui.event_bus import event_bus


class EndpointPipelineTests(unittest.TestCase):
    def _event(self, event_id, pid, parent_pid, process):
        return SecurityEvent(
            timestamp="2026-08-24T23:00:00",
            event_type=EventType.PROCESS_CREATION.value,
            severity="INFO",
            source="test",
            details={"pid": pid, "ppid": parent_pid, "name": process, "cmdline": process},
            event_id=event_id,
        )

    def test_process_chain_creates_incident_timeline_and_ui_event(self):
        with tempfile.TemporaryDirectory() as directory:
            original_cwd = os.getcwd()
            os.chdir(directory)
            try:
                engine = CyberOSEngine(config_path="missing.json")
                before = len(event_bus.get_history("incident_created"))
                engine._ingest_telemetry_event(self._event("evt-office", 100, 1, "winword.exe"))
                engine._ingest_telemetry_event(self._event("evt-shell", 101, 100, "cmd.exe"))

                incidents = engine.incident_manager.get_all_incidents()
                self.assertEqual(len(incidents), 1)
                incident = incidents[0]
                self.assertEqual(incident.events, ["evt-office", "evt-shell"])
                self.assertEqual(incident.attack_chain, ["winword.exe", "cmd.exe"])
                self.assertIn("T1059.001", incident.mitre_techniques)
                self.assertEqual(len(incident.forensic_timeline), 2)
                self.assertEqual(len(event_bus.get_history("incident_created")), before + 1)

                reloaded = IncidentManager(str(Path(directory) / "cyber_db" / "incidents.json"))
                self.assertEqual(len(reloaded.get_all_incidents()), 1)

                engine._ingest_telemetry_event(self._event("evt-office", 100, 1, "winword.exe"))
                engine._ingest_telemetry_event(self._event("evt-shell", 101, 100, "cmd.exe"))
                self.assertEqual(len(engine.incident_manager.get_all_incidents()), 1)
            finally:
                os.chdir(original_cwd)


if __name__ == "__main__":
    unittest.main()