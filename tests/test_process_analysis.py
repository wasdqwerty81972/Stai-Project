from ui.process_analysis import ProcessAnalysisWorker
from ui.process_analysis_state import ProcessAnalysisState


class Registry:
    def __init__(self, executable):
        self.process = {"pid": 44, "instance_id": "44:0x1", "exe": str(executable)}
        self.updates = []

    def get_process_details(self, instance_id):
        return dict(self.process) if instance_id == self.process["instance_id"] else None

    def update_process_fields(self, instance_id, fields):
        self.updates.append((instance_id, dict(fields)))
        self.process.update(fields)
        return dict(self.process)


def test_low_entropy_file_is_reported_without_triggering_scan(tmp_path):
    executable = tmp_path / "ordinary.exe"
    executable.write_bytes(b"A" * (256 * 1024))
    registry = Registry(executable)
    scans = []
    worker = ProcessAnalysisWorker(lambda: registry, lambda instance_id: scans.append(instance_id))

    result = worker.analyze("44:0x1")

    assert result["entropy_score"] == 0.0
    assert result["auto_scan_status"] == "not_triggered"
    assert scans == []


def test_high_entropy_file_queues_existing_scan_for_same_instance(tmp_path):
    executable = tmp_path / "packed.exe"
    executable.write_bytes(bytes(range(256)) * 1024)
    registry = Registry(executable)
    scans = []

    def scan(instance_id):
        scans.append(instance_id)
        return {"status": "clean", "sha256": "a" * 64, "rule_id": None, "action": "allow"}

    worker = ProcessAnalysisWorker(lambda: registry, scan, threshold=7.2)

    result = worker.analyze("44:0x1")

    assert result["entropy_score"] == 8.0
    assert result["auto_scan_status"] == "completed"
    assert result["scan_status"] == "clean"
    assert scans == ["44:0x1"]


def test_repeated_process_added_event_is_analyzed_once_after_worker_finishes(tmp_path):
    executable = tmp_path / "ordinary.exe"
    executable.write_bytes(b"A" * (256 * 1024))
    registry = Registry(executable)
    scans = []
    worker = ProcessAnalysisWorker(lambda: registry, lambda instance_id: scans.append(instance_id))
    worker.start()
    assert worker.enqueue(registry.process)
    worker._queue.join()
    assert worker.enqueue(registry.process)
    worker._queue.join()
    worker.stop()

    assert [fields.get("entropy_state") for _, fields in registry.updates].count("available") == 1
    assert scans == []


def test_service_analysis_evidence_stays_with_exact_process_instance_after_exit():
    class ServiceProvider:
        active = {"instance_id": "44:0x1p+0", "pid": 44, "exe": "C:/sample.exe"}

        def get_process_details(self, instance_id):
            return dict(self.active) if self.active and instance_id == self.active["instance_id"] else None

    provider = ServiceProvider()
    state = ProcessAnalysisState(lambda: (provider, "protection_service", None))
    state.remember(provider.active)
    provider.active = None

    result = state.update_process_fields("44:0x1p+0", {"scan_status": "detected", "scan_sha256": "a" * 64})

    assert result["pid"] == 44
    assert result["scan_status"] == "detected"
    assert state.get_process_details("44:0x1p+0")["scan_sha256"] == "a" * 64
    assert state.get_process_details("44:0x2p+0") is None
