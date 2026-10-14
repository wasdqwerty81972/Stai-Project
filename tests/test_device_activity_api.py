import unittest
from unittest.mock import patch

from fastapi import HTTPException
from starlette.requests import Request
from ui.api_server import device_activity


def request(host, origin=None):
    headers = [] if origin is None else [(b"origin", origin.encode())]
    return Request({"type": "http", "client": (host, 12345), "headers": headers})


class DeviceActivityAccessTests(unittest.IsolatedAsyncioTestCase):
    async def test_remote_client_cannot_read_processes(self):
        with self.assertRaises(HTTPException) as raised:
            await device_activity(request("192.0.2.1"))
        self.assertEqual(raised.exception.status_code, 403)

    async def test_untrusted_browser_origin_cannot_read_processes(self):
        with self.assertRaises(HTTPException) as raised:
            await device_activity(request("127.0.0.1", "https://example.com"))
        self.assertEqual(raised.exception.status_code, 403)

    async def test_native_loopback_client_receives_collector_snapshot(self):
        snapshot = {"processes": [{"pid": 42}]}
        with patch("ui.device_activity.get_device_activity", return_value=snapshot), patch(
            "ui.api_server._protection_pipe_request", return_value=None
        ):
            self.assertEqual(await device_activity(request("127.0.0.1")), snapshot)

    async def test_native_loopback_client_receives_authenticated_rule_metadata(self):
        snapshot = {"processes": [], "database": {"available": False, "version": None,
            "rule_count": 0, "demo": False, "coverage": "No authenticated threat database available"}}
        status = {"rules_trusted": True, "rules_version": "svs-eicar-demo-1",
            "rule_count": 1, "sha256_rule_count": 1, "yara_rule_count": 0}
        with patch("ui.device_activity.get_device_activity", return_value=snapshot) as activity, patch(
            "ui.api_server._protection_pipe_request", return_value=status
        ) as pipe_request:
            result = await device_activity(request("127.0.0.1"))

        self.assertEqual(result, snapshot)
        pipe_request.assert_called_once_with("get_rule_metadata", {}, timeout=0.75)
        activity.assert_called_once_with(status)
