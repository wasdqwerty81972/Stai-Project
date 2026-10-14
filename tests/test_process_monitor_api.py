import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from starlette.websockets import WebSocketDisconnect
from starlette.requests import Request

from ui.api_server import (
    _consume_service_process_analysis_batch,
    antivirus_process_connections,
    antivirus_process_detail,
    antivirus_process_events,
    antivirus_process_monitor_status,
    antivirus_processes,
    set_antivirus_process_monitor_profile,
    antivirus_process_stream,
)


def request(host="127.0.0.1", origin=None):
    headers = [] if origin is None else [(b"origin", origin.encode())]
    return Request({"type": "http", "client": (host, 12345), "headers": headers})


class Registry:
    def __init__(self):
        self.process = {"pid": 42, "instance_id": "42:0x1", "identity_verified": True}

    def snapshot(self):
        return {"sequence": 12, "processes": [self.process], "health": {"state": "running", "event_source": "degraded"}}

    def get_process(self, instance_id):
        return self.process if instance_id == self.process["instance_id"] else None

    def get_process_details(self, instance_id):
        return self.get_process(instance_id)

    def connections(self):
        return [
            {"instance_id": "42:0x1", "remote_address": "127.0.0.1"},
            {"instance_id": None, "remote_address": "192.0.2.1"},
        ]

    def set_sampling_profile(self, profile):
        if profile not in {"low", "normal", "high"}:
            raise ValueError("Sampling profile must be low, normal, or high")

    def drain_events(self, after_sequence):
        return [{"type": "process_metrics_updated", "sequence": 12}] if after_sequence < 12 else []


class WebSocket:
    def __init__(self, host="127.0.0.1", origin="http://localhost:3000"):
        self.client = SimpleNamespace(host=host)
        self.headers = {"origin": origin} if origin else {}
        self.sent = []
        self.close_code = None

    async def accept(self):
        pass

    async def send_json(self, payload):
        self.sent.append(payload)
        if len(self.sent) >= 2:
            raise WebSocketDisconnect()

    async def close(self, code=None):
        self.close_code = code


class ProcessMonitorApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_remote_client_is_rejected(self):
        with self.assertRaises(HTTPException) as raised:
            await antivirus_processes(request("192.0.2.1"))
        self.assertEqual(raised.exception.status_code, 403)

    async def test_untrusted_origin_is_rejected(self):
        with self.assertRaises(HTTPException) as raised:
            await antivirus_processes(request(origin="https://example.com"))
        self.assertEqual(raised.exception.status_code, 403)

    async def test_snapshot_and_health_are_real_registry_values(self):
        registry = Registry()
        with patch("ui.api_server._get_process_registry", return_value=registry):
            snapshot = await antivirus_processes(request())
            health = await antivirus_process_monitor_status(request())
        self.assertEqual(snapshot["processes"][0]["pid"], 42)
        self.assertEqual(health["event_source"], "degraded")

    async def test_running_windows_service_is_selected_as_process_source(self):
        from ui.api_server import _get_process_monitor_provider

        service = object()
        with (
            patch("ui.api_server.os.name", "nt"),
            patch("ui.api_server._get_process_registry") as local,
            patch("cyber_os.protection.windows_pipe_client.get_process_monitor_status", return_value={"state": "running"}),
            patch("ui.api_server._make_service_process_monitor", return_value=service),
        ):
            provider, source, error = _get_process_monitor_provider()
        self.assertIs(provider, service)
        self.assertEqual(source, "protection_service")
        self.assertIsNone(error)
        local.assert_not_called()

    async def test_service_pipe_failure_selects_truthfully_labeled_local_fallback(self):
        from ui.api_server import _get_process_monitor_provider

        registry = Registry()
        with (
            patch("ui.api_server.os.name", "nt"),
            patch("ui.api_server._get_process_registry", return_value=registry),
            patch("cyber_os.protection.windows_pipe_client.get_process_monitor_status", side_effect=TimeoutError("pipe timeout")),
        ):
            provider, source, error = _get_process_monitor_provider()
        self.assertIs(provider, registry)
        self.assertEqual(source, "local_fallback")
        self.assertIn("pipe timeout", error)

    async def test_status_exposes_local_fallback_reason_when_service_unavailable(self):
        registry = Registry()
        with (
            patch("ui.api_server.os.name", "nt"),
            patch("ui.api_server._get_process_registry", return_value=registry),
            patch("cyber_os.protection.windows_pipe_client.get_process_monitor_status", side_effect=TimeoutError("pipe timeout")),
        ):
            health = await antivirus_process_monitor_status(request())
        self.assertEqual(health["source"], "local_fallback")
        self.assertIn("pipe timeout", health["source_error"])

    async def test_stopped_local_collector_is_reported_as_unavailable(self):
        class StoppedRegistry(Registry):
            def snapshot(self):
                return {"sequence": 0, "processes": [], "health": {"state": "stopped"}}

        with (
            patch("ui.api_server.os.name", "nt"),
            patch("ui.api_server._get_process_registry", return_value=StoppedRegistry()),
            patch("cyber_os.protection.windows_pipe_client.get_process_monitor_status", side_effect=TimeoutError("pipe timeout")),
        ):
            health = await antivirus_process_monitor_status(request())
        self.assertEqual(health["source"], "unavailable")

    async def test_detail_uses_exact_instance_and_returns_404_when_gone(self):
        registry = Registry()
        with patch("ui.api_server._get_process_registry", return_value=registry):
            detail = await antivirus_process_detail("42:0x1", request())
            with self.assertRaises(HTTPException) as raised:
                await antivirus_process_detail("42:old", request())
        self.assertEqual(detail["instance_id"], "42:0x1")
        self.assertEqual(raised.exception.status_code, 404)

    async def test_connections_are_scoped_to_the_exact_instance(self):
        registry = Registry()
        with patch("ui.api_server._get_process_registry", return_value=registry):
            result = await antivirus_process_connections("42:0x1", request())
        self.assertEqual(len(result["connections"]), 1)
        self.assertEqual(result["connections"][0]["instance_id"], "42:0x1")

    async def test_event_cursor_reports_gap_and_returns_resync_snapshot(self):
        registry = Registry()
        with patch("ui.api_server._get_process_registry", return_value=registry):
            result = await antivirus_process_events(request(), after_sequence=3)
        self.assertTrue(result["resync_required"])
        self.assertEqual(result["snapshot"]["sequence"], 12)
        self.assertEqual(result["events"], [])

    async def test_event_cursor_returns_incremental_events_when_contiguous(self):
        registry = Registry()
        with patch("ui.api_server._get_process_registry", return_value=registry):
            result = await antivirus_process_events(request(), after_sequence=11)
        self.assertFalse(result["resync_required"])
        self.assertEqual(result["events"][0]["sequence"], 12)

    async def test_service_event_gap_returns_fresh_snapshot(self):
        class ServiceProvider:
            def read_events(self, after_sequence):
                return {"sequence": 18, "events": [], "resync_required": True}

        provider = ServiceProvider()
        snapshot = {"sequence": 18, "processes": [], "health": {"state": "running"}}
        with (
            patch("ui.api_server._get_process_monitor_provider", return_value=(provider, "protection_service", None)),
            patch("ui.api_server._process_snapshot_with_source", return_value=snapshot),
        ):
            result = await antivirus_process_events(request(), after_sequence=3)
        self.assertTrue(result["resync_required"])
        self.assertEqual(result["snapshot"]["sequence"], 18)
        self.assertEqual(result["source"], "protection_service")

    async def test_profile_change_is_local_and_validated(self):
        registry = Registry()
        with patch("ui.api_server._get_process_registry", return_value=registry):
            await set_antivirus_process_monitor_profile(request(), {"profile": "high"})
            with self.assertRaises(HTTPException) as raised:
                await set_antivirus_process_monitor_profile(request(), {"profile": "fastest"})
        self.assertEqual(raised.exception.status_code, 422)

    async def test_stream_sends_a_snapshot_then_sequenced_updates(self):
        class StreamingRegistry(Registry):
            def drain_events(self, after_sequence):
                return [{"type": "process_metrics_updated", "sequence": 13}] if after_sequence < 13 else []

        registry = StreamingRegistry()
        ws = WebSocket()
        with patch("ui.api_server._get_process_registry", return_value=registry):
            await antivirus_process_stream(ws)
        self.assertEqual(ws.sent[0]["type"], "snapshot")
        self.assertEqual(ws.sent[0]["sequence"], 12)
        self.assertEqual(ws.sent[1]["sequence"], 13)

    async def test_stream_uses_service_events_and_marks_service_source(self):
        class ServiceProvider:
            def snapshot(self):
                return {"sequence": 12, "processes": [], "health": {"state": "running"}}

            def read_events(self, after_sequence):
                if after_sequence < 13:
                    return {"sequence": 13, "events": [{"type": "process_added", "sequence": 13}], "resync_required": False}
                raise WebSocketDisconnect()

        ws = WebSocket()
        with patch(
            "ui.api_server._get_process_monitor_provider",
            return_value=(ServiceProvider(), "protection_service", None),
        ):
            await antivirus_process_stream(ws)
        self.assertEqual(ws.sent[0]["health"]["source"], "protection_service")
        self.assertEqual(ws.sent[1]["sequence"], 13)

    async def test_service_process_start_event_is_queued_without_metric_rescans(self):
        class Provider:
            def read_events(self, after_sequence):
                return {
                    "sequence": 6,
                    "resync_required": False,
                    "events": [
                        {"type": "process_metrics_updated", "sequence": 5},
                        {"type": "process_added", "sequence": 6, "process": {"instance_id": "9:0x1p+0", "pid": 9}},
                    ],
                }

        class Worker:
            queued = []

            def enqueue(self, process):
                self.queued.append(process)

        class State:
            def remember(self, process):
                return process

        worker = Worker()
        cursor = _consume_service_process_analysis_batch(Provider(), 4, worker, State())

        self.assertEqual(cursor, 6)
        self.assertEqual(worker.queued, [{"instance_id": "9:0x1p+0", "pid": 9}])

    async def test_stream_rejects_remote_clients_before_accept(self):
        ws = WebSocket(host="192.0.2.1")
        await antivirus_process_stream(ws)
        self.assertEqual(ws.close_code, 1008)
