from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from cyber_os.protection.network_telemetry import NetworkTelemetryCollector


class FakeNetworkProvider:
    def __init__(self):
        self.rows = []
        self.counters = {"Ethernet": {"bytes_recv": 1000, "bytes_sent": 500}}
        self.interface_rows = [{"name": "Ethernet", "is_up": True, "addresses": ["192.0.2.10"]}]
        self.processes = {}

    def connections(self):
        return self.rows

    def interface_counters(self):
        return self.counters

    def interfaces(self):
        return self.interface_rows

    def process_identity(self, pid):
        return self.processes.get(pid)


def connection(*, kind="tcp", family="ipv4", pid=42, local=("192.0.2.10", 50000), remote=("198.51.100.20", 443), status="ESTABLISHED"):
    return SimpleNamespace(kind=kind, family=family, pid=pid, laddr=local, raddr=remote, status=status)


def test_snapshot_preserves_tcp_udp_and_never_fabricates_direction_or_payload():
    provider = FakeNetworkProvider()
    provider.rows = [
        connection(),
        connection(kind="udp", local=("192.0.2.10", 5353), remote=(), status=""),
    ]
    provider.processes[42] = {
        "name": "browser.exe",
        "executable_path": "C:/Program Files/Browser/browser.exe",
        "create_time": 1234.5,
    }
    collector = NetworkTelemetryCollector(provider=provider)

    result = collector.snapshot()

    assert result["state"] == "active"
    assert [row["protocol"] for row in result["connections"]] == ["tcp", "udp"]
    assert result["connections"][0]["state"] == "ESTABLISHED"
    assert result["connections"][1]["state"] == "bound"
    assert result["connections"][0]["process_name"] == "browser.exe"
    assert result["connections"][0]["process_identity"] == "42:1234.500000"
    assert all(row["direction"] == "unknown" for row in result["connections"])
    assert result["coverage"]["payload_capture"] == "not_collected"
    assert result["coverage"]["per_process_bytes"] == "unavailable"


def test_interface_rates_use_counter_deltas_and_report_no_rate_on_first_sample():
    provider = FakeNetworkProvider()
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    collector = NetworkTelemetryCollector(provider=provider, clock=lambda: now[0])

    first = collector.snapshot()
    assert first["throughput"]["download_bytes_per_second"] is None
    assert first["throughput"]["upload_bytes_per_second"] is None

    provider.counters["Ethernet"] = {"bytes_recv": 3000, "bytes_sent": 1500}
    now[0] += timedelta(seconds=2)
    second = collector.snapshot()
    assert second["throughput"]["download_bytes_per_second"] == 1000
    assert second["throughput"]["upload_bytes_per_second"] == 500


def test_new_connection_events_are_emitted_once_per_observed_snapshot_lifetime():
    provider = FakeNetworkProvider()
    provider.rows = [connection()]
    collector = NetworkTelemetryCollector(provider=provider)

    first = collector.snapshot()
    repeated = collector.snapshot()
    provider.rows = []
    collector.snapshot()
    provider.rows = [connection()]
    reopened = collector.snapshot()

    assert len(first["new_connections"]) == 1
    assert repeated["new_connections"] == []
    assert len(reopened["new_connections"]) == 1


def test_provider_failure_is_unavailable_not_a_clean_empty_snapshot():
    class FailedProvider(FakeNetworkProvider):
        def connections(self):
            raise PermissionError("access denied")

    result = NetworkTelemetryCollector(provider=FailedProvider()).snapshot()

    assert result["state"] == "unavailable"
    assert result["connections"] is None
    assert result["errors"]
    assert result["coverage"]["connections"] == "unavailable"


def test_missing_optional_psutil_provider_returns_unavailable(monkeypatch):
    def unavailable_provider():
        raise RuntimeError("psutil is unavailable")

    monkeypatch.setattr("cyber_os.protection.network_telemetry.PsutilNetworkProvider", unavailable_provider)
    result = NetworkTelemetryCollector().snapshot()

    assert result["state"] == "unavailable"
    assert result["connections"] is None
    assert "provider enumeration unavailable" in result["errors"][0]


def test_process_lookup_failure_degrades_without_dropping_connection():
    class ProcessFailureProvider(FakeNetworkProvider):
        def process_identity(self, pid):
            raise PermissionError("access denied")

    provider = ProcessFailureProvider()
    provider.rows = [connection(pid=100)]
    result = NetworkTelemetryCollector(provider=provider).snapshot()

    assert result["state"] == "degraded"
    assert len(result["connections"]) == 1
    assert result["connections"][0]["pid"] == 100
    assert result["connections"][0]["process_name"] is None
