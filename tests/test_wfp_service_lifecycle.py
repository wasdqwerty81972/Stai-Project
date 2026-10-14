from __future__ import annotations

from cyber_os.protection.windows_service import ProtectionServiceHost
from cyber_os.protection.windows_service import _validate_pipe_request, process_pipe_request

import json


class _Store:
    def get_status(self, **kwargs):
        return {
            "state": "degraded",
            "driver_state": kwargs["driver_state"],
            "service_state": kwargs["service_state"],
            "rules_version": kwargs.get("rules_version", "unknown"),
            "last_scan": None,
            "counts": {"detected": 0, "blocked": 0, "quarantined": 0},
            "windows_security": {},
            "sensor_coverage": {},
            "last_error": kwargs.get("last_error"),
        }


class _Pipe:
    def start(self):
        pass

    def close(self):
        pass


class _NetworkMonitor:
    def __init__(self, *, start_result=True, start_error=None):
        self.start_result = start_result
        self.start_error = start_error
        self.start_calls = 0
        self.stop_calls = 0

    def start(self):
        self.start_calls += 1
        if self.start_error:
            raise self.start_error
        return self.start_result

    def stop(self, timeout=5.0):
        self.stop_calls += 1

    def get_status(self):
        return {"state": "observing" if self.start_result else "unavailable", "dropped": 0}

    def snapshot(self):
        return [{"sequence": index, "event_id": f"wfp:{index}"} for index in range(1, 4)]


def _host(network_monitor):
    return ProtectionServiceHost(
        store=_Store(),
        service=None,
        filter_client=None,
        pipe_server=_Pipe(),
        network_monitor=network_monitor,
        rules_trusted=False,
        windows_security_reader=lambda: None,
        health_refresh_seconds=3600,
    )


def test_wfp_monitor_has_independent_idempotent_lifecycle_and_health():
    monitor = _NetworkMonitor()
    host = _host(monitor)

    host.start()
    host.start()
    status = host.get_status()
    host.stop()

    assert monitor.start_calls == 1
    assert monitor.stop_calls == 1
    assert status["network_telemetry"] == {"state": "observing", "dropped": 0}
    assert status["state"] == "unavailable"
    assert status["driver_state"] == "stopped"


def test_wfp_monitor_start_failure_does_not_change_protection_state():
    monitor = _NetworkMonitor(start_error=PermissionError("BFE denied subscription"))
    host = _host(monitor)

    host.start()
    status = host.get_status()
    host.stop()

    assert monitor.start_calls == 1
    assert monitor.stop_calls == 1
    assert status["network_telemetry"]["state"] == "error"
    assert "permission" in status["network_telemetry"]["startup_error"].lower()
    assert status["state"] == "unavailable"


def test_missing_wfp_monitor_is_reported_as_not_configured():
    host = _host(None)
    status = host.get_status()
    host.stop()

    assert status["network_telemetry"]["state"] == "not_configured"
    assert status["state"] == "unavailable"


def test_network_telemetry_pipe_is_read_only_and_returns_bounded_recent_events():
    monitor = _NetworkMonitor()
    host = _host(monitor)
    request = {
        "version": 1,
        "request_id": "d" * 32,
        "operation": "get_network_telemetry",
        "payload": {},
    }

    assert _validate_pipe_request(request)[1] == "get_network_telemetry"
    response = json.loads(process_pipe_request(json.dumps(request).encode(), host))

    assert response["ok"] is True
    assert response["data"]["status"]["state"] == "observing"
    assert response["data"]["events"] == monitor.snapshot()


def test_network_telemetry_pipe_reports_unavailable_without_a_monitor():
    host = _host(None)
    request = {
        "version": 1,
        "request_id": "e" * 32,
        "operation": "get_network_telemetry",
        "payload": {},
    }

    response = json.loads(process_pipe_request(json.dumps(request).encode(), host))

    assert response["ok"] is True
    assert response["data"] == {"status": {"state": "not_configured"}, "events": []}


def test_network_telemetry_pipe_rejects_client_parameters():
    request = {
        "version": 1,
        "request_id": "f" * 32,
        "operation": "get_network_telemetry",
        "payload": {"block": True},
    }

    try:
        _validate_pipe_request(request)
    except ValueError as exc:
        assert "payload" in str(exc).lower()
    else:
        raise AssertionError("network telemetry pipe must not accept policy parameters")
