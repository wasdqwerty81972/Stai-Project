import threading

from ui.registry_device_activity import RegistryDeviceActivityCollector


class Monitor:
    def __init__(self):
        self.reads = 0
        self.collected = threading.Event()

    def snapshot(self):
        self.reads += 1
        self.collected.set()
        return {"observed_at": "2026-10-20T12:00:00Z", "processes": [{
            "pid": 42, "instance_id": "42:verified", "name": "shared.exe",
            "entropy_score": 0.0, "entropy_state": "available",
            "scan_status": "detected", "scan_action": "block", "scan_rule_id": "known-hash",
            "scan_rule_version": "trusted-1", "scan_sha256": "a" * 64,
        }], "health": {"state": "running"}}

    def connections(self):
        return [{"pid": 42, "instance_id": "42:verified", "process_name": "shared.exe",
                 "ownership_status": "verified_snapshot", "local_address": "::1",
                 "local_port": 5000, "remote_address": "::1", "remote_port": 443,
                 "protocol": "TCP", "state": "ESTABLISHED"}]

    def network_snapshot(self):
        return {"network": {"download_bytes_sec": 100, "upload_bytes_sec": 50,
                            "bytes_received": 1000, "bytes_sent": 500}}


def collector(monitor, *, trusted=True):
    return RegistryDeviceActivityCollector(
        lambda: (monitor, "protection_service", None),
        lambda row: row,
        lambda: {"rules_trusted": trusted, "rules_version": "trusted-1", "rule_count": 2,
                 "rules_fingerprint": "b" * 64},
        interval=60,
    )


def test_collection_starts_before_tabs_and_reads_return_cached_inventory():
    monitor = Monitor()
    activity = collector(monitor)
    activity.start()
    try:
        assert activity.ready.wait(2)
        first = activity.cached_snapshot()
        second = activity.cached_snapshot()
        assert monitor.reads == 1
        assert first["processes"][0]["pid"] == 42
        assert second["connections"][0]["remote_address"] == "[::1]:443"
        assert second["network"]["download_bytes_sec"] == 100
        first["processes"].clear()
        assert len(activity.cached_snapshot()["processes"]) == 1
    finally:
        activity.stop()


def test_verified_low_entropy_match_keeps_rule_evidence():
    activity = collector(Monitor())
    activity.refresh()
    assessment = activity.cached_snapshot()["processes"][0]["assessment"]
    assert assessment["classification"] == "known_threat"
    assert assessment["entropy"] == 0.0
    assert assessment["rule_id"] == "known-hash"


def test_untrusted_metadata_cannot_promote_a_match():
    activity = collector(Monitor(), trusted=False)
    activity.refresh()
    assert activity.cached_snapshot()["processes"][0]["assessment"]["classification"] == "unavailable"


def test_refresh_failure_preserves_last_snapshot_and_reports_staleness():
    monitor = Monitor()
    activity = collector(monitor)
    activity.refresh()

    def failed():
        raise OSError("pipe unavailable")

    monitor.snapshot = failed
    activity.refresh()
    snapshot = activity.cached_snapshot()
    assert snapshot["processes"][0]["pid"] == 42
    assert snapshot["stale"] is True
    assert any("pipe unavailable" in error for error in snapshot["errors"])
