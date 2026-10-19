"""FastAPI lifecycle and loopback protection for communications controls."""

from __future__ import annotations

from fastapi.testclient import TestClient

from ui.api_server import app


def test_communications_gateway_starts_and_stops_without_platform_secrets() -> None:
    with TestClient(app, client=("127.0.0.1", 12345), headers={"Origin": "http://127.0.0.1:6763"}) as client:
        response = client.get("/api/communications/status")
        assert response.status_code == 200
        body = response.json()
        assert body["settings"]["enabled"] == {"discord": False, "telegram": False}
        assert body["platforms"]["discord"]["status"] == "Disconnected"
        assert body["platforms"]["telegram"]["status"] == "Disconnected"
    assert getattr(app.state, "communications_manager", None) is not None


def test_communications_administration_rejects_non_loopback_clients() -> None:
    with TestClient(app, client=("192.0.2.20", 12345), headers={"Origin": "http://127.0.0.1:6763"}) as client:
        response = client.get("/api/communications/status")
        assert response.status_code == 403


def test_communications_administration_rejects_untrusted_browser_origins() -> None:
    with TestClient(app, client=("127.0.0.1", 12345), headers={"Origin": "https://attacker.example"}) as client:
        response = client.get("/api/communications/status")
        assert response.status_code == 403
