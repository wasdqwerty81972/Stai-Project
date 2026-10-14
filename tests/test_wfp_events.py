from __future__ import annotations

import ctypes
import time
import pytest

from cyber_os.network_telemetry.wfp_events import (
    FIELD_APP_ID,
    FIELD_DIRECTION,
    FIELD_IP_VERSION,
    FIELD_LAYER,
    FIELD_LOCAL_ADDRESS,
    FIELD_LOCAL_PORT,
    FIELD_LOOPBACK,
    FIELD_PROTOCOL,
    FIELD_REAUTH_REASON,
    FIELD_REMOTE_ADDRESS,
    FIELD_REMOTE_PORT,
    FIELD_TIMESTAMP,
    FIELD_USER_SID,
    NATIVE_EVENT_VERSION,
    NativeEventRecord,
    WfpNetEventMonitor,
    WfpNetEventSubscription,
    WfpSubscriptionError,
    decode_native_event,
)


def _record() -> NativeEventRecord:
    record = NativeEventRecord()
    record.size = ctypes.sizeof(NativeEventRecord)
    record.version = NATIVE_EVENT_VERSION
    record.sequence = 7
    record.timestamp_filetime = 133801632000000000
    record.field_flags = (
        FIELD_TIMESTAMP
        | FIELD_IP_VERSION
        | FIELD_PROTOCOL
        | FIELD_LOCAL_ADDRESS
        | FIELD_REMOTE_ADDRESS
        | FIELD_LOCAL_PORT
        | FIELD_REMOTE_PORT
        | FIELD_APP_ID
        | FIELD_USER_SID
        | FIELD_DIRECTION
        | FIELD_LAYER
        | FIELD_LOOPBACK
        | FIELD_REAUTH_REASON
    )
    record.event_type = 1
    record.ip_version = 4
    record.protocol = 6
    record.direction = 2
    record.layer_id = 48
    record.reauth_reason = 3
    record.is_loopback = 0
    record.local_port = 51432
    record.remote_port = 443
    record.local_address[:4] = (192, 0, 2, 20)
    record.remote_address[:4] = (198, 51, 100, 8)
    app_id = b"opaque-app-id"
    record.app_id_len = len(app_id)
    record.app_id[: len(app_id)] = app_id
    sid = bytes.fromhex("010100000000000512000000")
    record.user_sid_len = len(sid)
    record.user_sid[: len(sid)] = sid
    return record


def test_decode_normalizes_only_fields_reported_by_native_flags():
    event = decode_native_event(_record())

    assert event.sequence == 7
    assert event.timestamp_utc == "2025-01-01T00:00:00+00:00"
    assert event.event_type == "classify_allow"
    assert event.observed_action == "allow"
    assert event.ip_version == 4
    assert event.protocol == 6
    assert event.local_address == "192.0.2.20"
    assert event.remote_address == "198.51.100.8"
    assert event.local_port == 51432
    assert event.remote_port == 443
    assert event.app_id_hex == b"opaque-app-id".hex()
    assert event.user_sid == "S-1-5-18"
    assert event.direction == "outbound"
    assert event.layer_id == 48
    assert event.reauth_reason == 3
    assert event.is_loopback is False
    assert event.process_id is None


def test_decode_leaves_unflagged_values_unavailable():
    record = _record()
    record.field_flags = 0
    record.timestamp_filetime = 123
    record.ip_version = 6
    record.protocol = 17
    record.local_port = 1
    record.app_id_len = 4
    record.user_sid_len = 12
    event = decode_native_event(record)

    assert event.timestamp_utc is None
    assert event.ip_version is None
    assert event.protocol is None
    assert event.local_address is None
    assert event.remote_address is None
    assert event.local_port is None
    assert event.app_id_hex is None
    assert event.user_sid is None
    assert event.direction is None
    assert event.layer_id is None
    assert event.reauth_reason is None
    assert event.is_loopback is None
    assert event.process_id is None


def test_decode_handles_ipv6_and_drop_events():
    record = _record()
    record.event_type = 2
    record.ip_version = 6
    record.local_address[:] = bytes.fromhex("20010db8000000000000000000000001")
    record.remote_address[:] = bytes.fromhex("20010db8000000000000000000000002")
    event = decode_native_event(record)

    assert event.event_type == "classify_drop"
    assert event.observed_action == "drop"
    assert event.local_address == "2001:db8::1"
    assert event.remote_address == "2001:db8::2"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda record: setattr(record, "version", NATIVE_EVENT_VERSION + 1),
        lambda record: setattr(record, "size", ctypes.sizeof(NativeEventRecord) - 1),
        lambda record: setattr(record, "event_type", 999),
        lambda record: setattr(record, "ip_version", 5),
    ],
)
def test_decode_rejects_invalid_native_records(mutation):
    record = _record()
    mutation(record)

    with pytest.raises(ValueError):
        decode_native_event(record)


def test_subscription_uses_injected_bridge_and_closes_once():
    class Bridge:
        def __init__(self):
            self.starts = 0
            self.stops = 0
            self.records = [_record()]

        def start(self):
            self.starts += 1
            return 0

        def stop(self):
            self.stops += 1
            return 0

        def read_one(self):
            return self.records.pop(0) if self.records else None

        def stats(self):
            return {
                "state": "running",
                "queued": len(self.records),
                "dropped": 0,
                "last_sequence": 7,
                "last_error": 0,
            }

    bridge = Bridge()
    subscription = WfpNetEventSubscription(bridge)

    subscription.start()
    events = subscription.poll(max_events=1)
    stats = subscription.stats()
    subscription.close()
    subscription.close()

    assert bridge.starts == 1
    assert bridge.stops == 1
    assert events[0].sequence == 7
    assert stats.queued == 0


def test_subscription_rejects_double_start_and_bad_poll_limits():
    class Bridge:
        def start(self):
            return 0

        def stop(self):
            return 0

        def read_one(self):
            return None

        def stats(self):
            return {
                "state": "running",
                "queued": 0,
                "dropped": 0,
                "last_sequence": 0,
                "last_error": 0,
            }

    subscription = WfpNetEventSubscription(Bridge())
    subscription.start()
    with pytest.raises(WfpSubscriptionError):
        subscription.start()
    with pytest.raises(ValueError):
        subscription.poll(max_events=0)
    subscription.close()


def test_monitor_reports_unavailable_when_native_dll_is_missing_without_raising(monkeypatch):
    monkeypatch.delenv("STAI_WFP_EVENT_BRIDGE", raising=False)
    monitor = WfpNetEventMonitor(dll_path="missing-wfp-event-bridge.dll")

    assert monitor.start() is False
    status = monitor.get_status()
    assert status["state"] == "unavailable"
    assert "missing-wfp-event-bridge.dll" in status["last_error"]
    assert monitor.snapshot() == []
    assert monitor.stop(timeout=0.1) is True


def test_monitor_polls_events_and_keeps_bounded_snapshot():
    class Bridge:
        def __init__(self):
            self.records = [_record(), _record(), _record()]
            self.starts = 0
            self.stops = 0

        def start(self):
            self.starts += 1
            return 0

        def stop(self):
            self.stops += 1
            return 0

        def read_one(self):
            return self.records.pop(0) if self.records else None

        def stats(self):
            return {
                "state": "running",
                "queued": len(self.records),
                "dropped": 0,
                "last_sequence": 7,
                "last_error": 0,
            }

    bridge = Bridge()
    monitor = WfpNetEventMonitor(
        bridge=bridge,
        poll_interval=0.005,
        history_limit=2,
    )
    assert monitor.start() is True

    deadline = time.monotonic() + 1
    while len(monitor.snapshot()) < 2 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert monitor.stop(timeout=1) is True

    assert bridge.starts == 1
    assert bridge.stops == 1
    assert len(monitor.snapshot()) == 2
    assert monitor.get_status()["state"] == "stopped"
