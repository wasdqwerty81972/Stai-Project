import psutil

from ui.device_process_identity import process_identity
from ui.process_monitor import ProcessRegistry
from ui.windows_process_events import SourceStatus


def test_registry_tracks_process_start_with_creation_time_identity():
    registry = ProcessRegistry(event_history_limit=8)

    registry.reconcile([{"pid": 42, "name": "app.exe", "create_time": 100.5}])

    snapshot = registry.snapshot()
    process = snapshot["processes"][0]
    assert process["instance_id"] == process_identity(42, 100.5)
    assert process["identity_verified"] is True
    assert registry.get_process(process["instance_id"])["name"] == "app.exe"
    assert [event["type"] for event in registry.drain_events(0)] == ["process_added"]


def test_process_added_callback_and_async_update_preserve_exact_instance():
    analyzed = []
    registry = ProcessRegistry(on_process_added=analyzed.append, event_history_limit=8)
    registry.reconcile([{"pid": 42, "name": "app.exe", "create_time": 100.5}])
    instance_id = registry.snapshot()["processes"][0]["instance_id"]

    updated = registry.update_process_fields(instance_id, {"entropy_score": 7.8, "entropy_state": "available"})

    assert analyzed[0]["instance_id"] == instance_id
    assert updated["entropy_score"] == 7.8
    event = registry.drain_events(1)[0]
    assert event["type"] == "process_metrics_updated"
    assert event["process"]["instance_id"] == instance_id


def test_pid_reuse_removes_old_instance_and_adds_new_instance():
    registry = ProcessRegistry(event_history_limit=8)
    registry.reconcile([{"pid": 42, "name": "old.exe", "create_time": 100.5}])
    old_id = registry.snapshot()["processes"][0]["instance_id"]

    registry.reconcile([{"pid": 42, "name": "new.exe", "create_time": 101.5}])

    new_id = registry.snapshot()["processes"][0]["instance_id"]
    assert new_id != old_id
    assert registry.get_process(old_id) is None
    assert registry.get_process(new_id)["name"] == "new.exe"
    assert [event["type"] for event in registry.drain_events(1)] == [
        "process_removed", "process_added"
    ]


def test_process_without_creation_time_is_partial_and_not_keyed_by_pid_alone():
    registry = ProcessRegistry(event_history_limit=8)

    registry.reconcile([{"pid": 43, "name": "restricted.exe", "create_time": None}])

    process = registry.snapshot()["processes"][0]
    assert process["identity_verified"] is False
    assert process["instance_id"] != "43"
    assert process["create_time"] is None


def test_unverified_process_keeps_the_same_display_identity_between_snapshots():
    registry = ProcessRegistry(event_history_limit=8)
    row = {"pid": 43, "name": "restricted.exe", "create_time": None}
    registry.reconcile([row])
    first_id = registry.snapshot()["processes"][0]["instance_id"]

    registry.reconcile([row])

    assert registry.snapshot()["processes"][0]["instance_id"] == first_id


def test_stop_event_older_than_current_pid_instance_does_not_remove_it():
    registry = ProcessRegistry(event_history_limit=8)
    registry.reconcile([{"pid": 42, "name": "new.exe", "create_time": 101.5}])
    instance_id = registry.snapshot()["processes"][0]["instance_id"]

    registry.process_stopped({"pid": 42, "event_time": 101.0})

    assert registry.get_process(instance_id) is not None


def test_event_history_is_bounded_without_reusing_sequence_numbers():
    registry = ProcessRegistry(event_history_limit=2)
    registry.reconcile([{"pid": 1, "name": "one.exe", "create_time": 1.0}])
    registry.reconcile([{"pid": 2, "name": "two.exe", "create_time": 2.0}])
    registry.reconcile([])

    events = registry.drain_events(0)
    assert len(events) == 2
    assert events[0]["sequence"] < events[1]["sequence"]
    assert events[-1]["type"] == "process_removed"


def test_detail_metadata_is_loaded_only_for_the_matching_process_instance(monkeypatch):
    registry = ProcessRegistry()
    registry.reconcile([{"pid": 42, "name": "worker.exe", "create_time": 100.5}])
    instance_id = registry.snapshot()["processes"][0]["instance_id"]

    class Process:
        def as_dict(self, **kwargs):
            return {"create_time": 100.5, "ppid": 7, "username": "user",
                    "exe": "C:/worker.exe", "status": "sleeping", "num_threads": 3}

    monkeypatch.setattr(psutil, "Process", lambda pid: Process())

    detail = registry.get_process_details(instance_id)

    assert detail["exe"] == "C:/worker.exe"
    assert detail["parent_pid"] == 7
    assert detail["status"] == "sleeping"


def test_detail_metadata_does_not_cross_pid_reuse(monkeypatch):
    registry = ProcessRegistry()
    registry.reconcile([{"pid": 42, "name": "old.exe", "create_time": 100.5}])
    instance_id = registry.snapshot()["processes"][0]["instance_id"]

    class Process:
        def as_dict(self, **kwargs):
            return {"create_time": 101.5}

    monkeypatch.setattr(psutil, "Process", lambda pid: Process())
    reconciles = []
    monkeypatch.setattr(registry, "reconcile", lambda: reconciles.append(True))

    assert registry.get_process_details(instance_id) is None
    assert reconciles == [True]


def test_lightweight_reconciliation_does_not_erase_sampled_detail_metadata():
    registry = ProcessRegistry()
    registry.reconcile([{"pid": 42, "name": "worker.exe", "create_time": 100.5}])
    instance_id = registry.snapshot()["processes"][0]["instance_id"]
    registry.upsert_process({"pid": 42, "name": "worker.exe", "create_time": 100.5, "exe": "C:/worker.exe"})

    registry.reconcile([{"pid": 42, "name": "worker.exe", "create_time": 100.5, "exe": None}])

    assert registry.get_process(instance_id)["exe"] == "C:/worker.exe"


def test_sampling_profiles_expose_their_real_collection_intervals():
    registry = ProcessRegistry()

    registry.set_sampling_profile("high")

    health = registry.snapshot()["health"]
    assert health["sampling_profile"] == "high"
    assert health["sample_interval_seconds"] == 1.0
    assert health["reconcile_interval_seconds"] == 2.0


def test_health_reports_event_source_denial_and_live_reconciliation():
    class DeniedSource:
        status = SourceStatus("unavailable", "subscription denied", 3)

        def start(self, _on_start, _on_exit):
            return self.status

        def stop(self):
            return None

    registry = ProcessRegistry(
        process_provider=lambda: [],
        event_source=DeniedSource(),
        sample_interval=10.0,
        reconcile_interval=10.0,
    )
    registry.start()
    try:
        registry.sample_metrics([])
        health = registry.health()

        assert health["state"] == "running"
        assert health["event_source"] == "unavailable"
        assert health["event_source_error"] == "subscription denied"
        assert health["dropped_events"] == 3
        assert health["last_reconcile_seconds_ago"] is not None
        assert health["last_sample_seconds_ago"] is not None
    finally:
        registry.stop()


def test_slow_metric_sample_does_not_starve_process_reconciliation():
    import threading
    import time

    from ui.process_monitor import ProcessRegistry
    from ui.windows_process_events import WindowsProcessEventSource

    registry = ProcessRegistry(
        process_provider=lambda: [],
        event_source=WindowsProcessEventSource(platform_supported=False),
        sample_interval=0.25,
        reconcile_interval=0.25,
    )
    reconciliations = 0
    original_reconcile = registry.reconcile
    reconciled = threading.Event()

    def count_reconcile(*args, **kwargs):
        nonlocal reconciliations
        reconciliations += 1
        if reconciliations > 1:
            reconciled.set()
        return original_reconcile(*args, **kwargs)

    registry.reconcile = count_reconcile
    registry.sample_metrics = lambda: time.sleep(0.30)
    registry.connections = lambda: []
    registry.start()
    try:
        assert reconciled.wait(0.5), "a slow metric sample delayed reconciliation past its due interval"
    finally:
        registry.stop()


def test_lightweight_reconciliation_does_not_query_parent_pid_for_every_process(monkeypatch):
    from types import SimpleNamespace

    requested = {}
    monkeypatch.setattr(
        "ui.process_monitor.psutil.process_iter",
        lambda *, attrs, ad_value: requested.update(attrs=attrs) or [
            SimpleNamespace(pid=55, info={"name": "child.exe", "create_time": 55.0})
        ],
    )

    rows = ProcessRegistry._enumerate_processes()

    assert "ppid" not in requested["attrs"]
    assert rows[0]["parent_pid"] is None
