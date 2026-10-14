"""Contract tests for the Windows Protection API routes."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from cyber_os.protection.models import ThreatIntelEvidence
from ui import api_server as server


@pytest.fixture
def mock_protection_service():
    """Create a mock protection service with predictable responses."""
    store = MagicMock()
    store.get_status.return_value = SimpleNamespace(
        state="active",
        driver_state="running",
        service_state="running",
        rules_version="test-1",
        last_scan="2026-01-01T00:00:00",
        counts={"detected": 5, "blocked": 2, "quarantined": 1},
        windows_security={"registered_av_provider": "Windows Defender", "defender_mode": "enabled", "query_available": True},
        sensor_coverage={},
        last_error=None,
    )
    store.list_threats.return_value = []
    store.create_scan_job.return_value = SimpleNamespace(
        job_id="job-1", scope="quick", state="running", files_scanned=10, files_total=100, detections=1, errors=0, started_at="2026-01-01T00:00:00", completed_at=None, error_message=None
    )
    store.get_scan_job.return_value = SimpleNamespace(
        job_id="job-1", scope="quick", state="completed", files_scanned=100, files_total=100, detections=1, errors=0, started_at="2026-01-01T00:00:00", completed_at="2026-01-01T00:01:00", error_message=None
    )
    store.update_scan_job.return_value = True

    service = SimpleNamespace(
        store=store,
        scan_file=MagicMock(return_value=SimpleNamespace(
            status="clean", action="allow", rule_id=None, rule_version="test-1", sha256="a" * 64, reason="no match"
        )),
        start_scan=MagicMock(return_value=SimpleNamespace(
            job_id="job-1", scope="quick", state="running", files_scanned=0, files_total=100, detections=0, errors=0, started_at="2026-01-01T00:00:00", completed_at=None, error_message=None
        )),
        cancel_scan=MagicMock(return_value=True),
        quarantine_detection=MagicMock(return_value=SimpleNamespace(success=True, item=SimpleNamespace(
            item_id="item-1", original_path="C:\\test.exe", quarantined_path="C:\\quarantine\\item-1.stai_quarantine", sha256="a" * 64, rule_id="hash-1", rule_version="test-1", action_result="moved", detection_id="det-1", created_at="2026-01-01T00:00:00", restored_at=None, restore_result=None
        ), error=None)),
        restore_quarantine=MagicMock(return_value=SimpleNamespace(success=True, item=SimpleNamespace(
            item_id="item-1", original_path="C:\\test.exe", quarantined_path="C:\\quarantine\\item-1.stai_quarantine", sha256="a" * 64, rule_id="hash-1", rule_version="test-1", action_result="moved", detection_id="det-1", created_at="2026-01-01T00:00:00", restored_at="2026-01-01T00:05:00", restore_result="restored"
        ), error=None)),
        list_quarantine=MagicMock(return_value=[]),
        get_status=MagicMock(return_value=SimpleNamespace(
            state="active", driver_state="running", service_state="running", rules_version="test-1", last_scan="2026-01-01T00:00:00", counts={"detected": 5, "blocked": 2, "quarantined": 1}, windows_security={"registered_av_provider": "Windows Defender", "defender_mode": "enabled", "query_available": True}, sensor_coverage={}, last_error=None
        )),
        rules=SimpleNamespace(version="test-1", rules=()),
        rules_trust_established=True,
        threat_intel_status=MagicMock(return_value={"state": "advisory", "integrity_ok": True, "block_eligible_records": 42, "activation": "inactive"}),
    )

    return service


@pytest.fixture
def protection_client(mock_protection_service, monkeypatch):
    """Create a test client with mocked protection service."""
    monkeypatch.setattr(server, "_get_protection_service", lambda: mock_protection_service)
    with TestClient(server.app) as client:
        yield client


def _reset_protection_service_mock():
    """Helper to clear the protection service singleton."""
    if hasattr(server, "_protection_service"):
        delattr(server, "_protection_service")


def test_status_reports_degraded_when_driver_or_rules_unhealthy(monkeypatch, mock_protection_service):
    _reset_protection_service_mock()
    mock_protection_service.get_status.return_value = SimpleNamespace(
        state="degraded",
        driver_state="stopped",
        service_state="running",
        rules_version="test-1",
        last_scan=None,
        counts={"detected": 0, "blocked": 0, "quarantined": 0},
        windows_security={"registered_av_provider": None, "defender_mode": None, "query_available": False},
        sensor_coverage={},
        last_error="driver not loaded",
    )
    monkeypatch.setattr(server, "_get_protection_service", lambda: mock_protection_service)

    with TestClient(server.app) as client:
        reply = client.get("/api/protection/status")

    assert reply.status_code == 200
    data = reply.json()
    assert data["state"] == "degraded"
    assert data["driver_state"] == "stopped"


def test_status_exposes_advisory_intelligence_health(protection_client, mock_protection_service):
    response = protection_client.get("/api/protection/status")
    assert response.status_code == 200
    assert response.json()["threat_intel"] == {
        "state": "advisory",
        "integrity_ok": True,
        "block_eligible_records": 42,
        "activation": "inactive",
    }


def test_threat_list_returns_structured_hash_intel_evidence(protection_client, mock_protection_service):
    evidence = ThreatIntelEvidence(
        indicator_type="sha256",
        indicator_value="a" * 64,
        source="abusech_malwarebazaar",
        verification="confirmed",
        confidence=95,
        severity="high",
        feed_version="feed-42",
        first_seen="2026-10-14T10:00:00",
        last_seen="2026-10-14T11:00:00",
        freshness="fresh",
        corroborations=1,
        block_eligible=True,
        decision_reason="eligible in store; advisory in P2A",
    )
    mock_protection_service.store.list_threats.return_value = [SimpleNamespace(
        detection_id="det-1", sha256="a" * 64, rule_id="threat-intel-advisory",
        rule_version="feed-42", action="allow", confidence="low", severity="high",
        file_type=".exe", size_bytes=10, file_path="C:/sample.exe",
        created_at="2026-10-14T12:00:00", triage_enqueued=False, intel_evidence=evidence,
    )]
    response = protection_client.get("/api/protection/threats")
    assert response.status_code == 200
    assert response.json()[0]["threat_intel_evidence"]["source"] == "abusech_malwarebazaar"
    assert response.json()[0]["threat_intel_evidence"]["block_eligible"] is True


def test_status_includes_registered_av_and_defender_mode_when_available(monkeypatch, mock_protection_service):
    _reset_protection_service_mock()
    mock_protection_service.get_status.return_value = SimpleNamespace(
        state="active",
        driver_state="running",
        service_state="running",
        rules_version="test-1",
        last_scan="2026-01-01T00:00:00",
        counts={"detected": 1, "blocked": 0, "quarantined": 0},
        windows_security={"registered_av_provider": "Windows Defender", "defender_mode": "enabled", "query_available": True},
        sensor_coverage={},
        last_error=None,
    )
    monkeypatch.setattr(server, "_get_protection_service", lambda: mock_protection_service)

    with TestClient(server.app) as client:
        reply = client.get("/api/protection/status")

    assert reply.status_code == 200
    data = reply.json()
    assert data["windows_security"]["registered_av_provider"] == "Windows Defender"
    assert data["windows_security"]["defender_mode"] == "enabled"
    assert data["windows_security"]["query_available"] is True


def test_status_never_reports_active_when_rules_trust_is_unestablished(monkeypatch, mock_protection_service):
    mock_protection_service.rules_trust_established = False
    mock_protection_service.get_status.return_value = SimpleNamespace(
        state="active",
        driver_state="running",
        service_state="running",
        rules_version="rules-7",
        last_scan=None,
        counts={"detected": 0, "blocked": 0, "quarantined": 0},
        windows_security={"registered_av_provider": None, "defender_mode": None, "query_available": False},
        sensor_coverage={},
        last_error=None,
    )
    monkeypatch.setattr(server, "_get_protection_service", lambda: mock_protection_service)

    with TestClient(server.app) as client:
        reply = client.get("/api/protection/status")

    assert reply.status_code == 200
    assert reply.json()["state"] == "degraded"
    assert "trust" in reply.json()["last_error"].lower()


def test_status_never_reports_active_for_dev_empty_rules(monkeypatch, mock_protection_service):
    mock_protection_service.rules_trust_established = True
    mock_protection_service.get_status.return_value = SimpleNamespace(
        state="active",
        driver_state="running",
        service_state="running",
        rules_version="dev-empty",
        last_scan=None,
        counts={"detected": 0, "blocked": 0, "quarantined": 0},
        windows_security={"registered_av_provider": None, "defender_mode": None, "query_available": False},
        sensor_coverage={},
        last_error=None,
    )
    monkeypatch.setattr(server, "_get_protection_service", lambda: mock_protection_service)

    with TestClient(server.app) as client:
        reply = client.get("/api/protection/status")

    assert reply.status_code == 200
    assert reply.json()["state"] == "degraded"
    assert "empty" in reply.json()["last_error"].lower()


def test_local_dev_empty_bootstrap_is_reported_as_degraded(monkeypatch, tmp_path):
    ui_dir = tmp_path / "ui"
    ui_dir.mkdir()
    monkeypatch.setattr(server, "__file__", str(ui_dir / "api_server.py"))
    monkeypatch.setattr(server, "_protection_service", None, raising=False)
    service = server._get_protection_service()
    monkeypatch.setattr(server, "_get_protection_service", lambda: service)

    with TestClient(server.app) as client:
        reply = client.get("/api/protection/status")

    assert reply.status_code == 200
    assert reply.json()["rules_version"] == "dev-empty"
    assert reply.json()["rules_trust_established"] is False
    assert reply.json()["state"] == "degraded"


def test_scan_rejects_client_supplied_paths(monkeypatch, mock_protection_service):
    _reset_protection_service_mock()
    monkeypatch.setattr(server, "_get_protection_service", lambda: mock_protection_service)

    with TestClient(server.app) as client:
        reply = client.post("/api/protection/scans", json={"scope": "quick", "roots": ["C:/"]})

    assert reply.status_code == 422  # validation error


def test_scan_job_routes_report_persisted_progress(monkeypatch, mock_protection_service):
    _reset_protection_service_mock()
    mock_protection_service.start_scan.return_value = SimpleNamespace(
        job_id="job-123", scope="quick", state="running", files_scanned=50, files_total=100, detections=2, errors=0, files_skipped=3, unknown_verdicts=1, started_at="2026-01-01T00:00:00", completed_at=None, error_message=None
    )
    mock_protection_service.store.get_scan_job.return_value = SimpleNamespace(
        job_id="job-123", scope="quick", state="completed", files_scanned=100, files_total=100, detections=2, errors=0, files_skipped=3, unknown_verdicts=1, started_at="2026-01-01T00:00:00", completed_at="2026-01-01T00:02:00", error_message=None
    )
    monkeypatch.setattr(server, "_get_protection_service", lambda: mock_protection_service)

    with TestClient(server.app) as client:
        # Start scan
        start_reply = client.post("/api/protection/scans", json={"scope": "quick"})
        assert start_reply.status_code == 200
        job = start_reply.json()
        assert job["job_id"] == "job-123"
        assert job["files_total"] == 100
        assert job["files_skipped"] == 3
        assert job["unknown_verdicts"] == 1

        # Get scan progress
        get_reply = client.get("/api/protection/scans/job-123")
        assert get_reply.status_code == 200
        progress = get_reply.json()
        assert progress["files_scanned"] == 100
        assert progress["state"] == "completed"
        assert progress["files_skipped"] == 3
        assert progress["unknown_verdicts"] == 1


def test_threats_endpoint_does_not_conflate_detected_and_blocked(monkeypatch, mock_protection_service):
    _reset_protection_service_mock()
    # Return detections with different actions
    mock_protection_service.store.list_threats.return_value = [
        SimpleNamespace(detection_id="det-1", sha256="a" * 64, rule_id="hash-1", rule_version="test-1", action="block", confidence="high", severity="critical", file_type=".exe", size_bytes=1024, file_path="C:\\bad.exe", created_at="2026-01-01T00:00:00", triage_enqueued=False),
        SimpleNamespace(detection_id="det-2", sha256="b" * 64, rule_id="yara-1", rule_version="test-1", action="allow", confidence="low", severity="medium", file_type=".exe", size_bytes=2048, file_path="C:\\obs.exe", created_at="2026-01-01T00:01:00", triage_enqueued=False),
    ]
    monkeypatch.setattr(server, "_get_protection_service", lambda: mock_protection_service)

    with TestClient(server.app) as client:
        reply = client.get("/api/protection/threats")

    assert reply.status_code == 200
    data = reply.json()
    assert len(data) == 2
    blocked = [d for d in data if d["action"] == "block"]
    observed = [d for d in data if d["action"] == "allow"]
    assert len(blocked) == 1
    assert len(observed) == 1
    assert blocked[0]["rule_id"] == "hash-1"
    assert observed[0]["rule_id"] == "yara-1"


def test_restore_requires_existing_quarantine_item(monkeypatch, mock_protection_service):
    _reset_protection_service_mock()
    mock_protection_service.restore_quarantine.return_value = SimpleNamespace(success=False, item=None, error="quarantine item not found")
    monkeypatch.setattr(server, "_get_protection_service", lambda: mock_protection_service)

    with TestClient(server.app) as client:
        reply = client.post("/api/protection/quarantine/nonexistent/restore")

    assert reply.status_code == 404


def test_protection_agent_chat_cannot_execute_tools(monkeypatch, tmp_path):
    from cyber_os.protection.store import DetectionRecord, ProtectionStore
    from cyber_os.protection.triage import ProtectionTriage

    class Provider:
        available = True

        def analyze(self, context):
            return "Analysis complete"

        def respond(self, context, history, message):
            self.context = context
            self.message = message
            return "Analysis complete"

    store = ProtectionStore(tmp_path / "protection.db")
    store.record_detection(DetectionRecord(
        detection_id="det-1", sha256="a" * 64, rule_id="hash-1", rule_version="rules-7",
        action="block", confidence="high", severity="critical", file_type=".exe", size_bytes=1024,
        file_path=r"C:\Users\Alice\Desktop\sample.exe", created_at="2026-01-01T00:00:00",
        triage_enqueued=False,
    ))
    provider = Provider()
    triage = ProtectionTriage(store, provider)
    monkeypatch.setattr(server, "_get_protection_triage", lambda: triage, raising=False)

    with TestClient(server.app) as client:
        reply = client.post("/api/protection/agent/messages", json={
            "session_id": "sess-1",
            "message": "Analyze this detection",
            "detection_id": "det-1"
        })

    assert reply.status_code == 200
    data = reply.json()
    assert data["tool_calls"] == []
    assert data["response_action"] is None
    assert "message" in data
    assert "C:\\Users" not in repr(provider.context)


def test_protection_triage_routes_schedule_and_retrieve_separate_result(monkeypatch, tmp_path):
    from cyber_os.protection.store import DetectionRecord, ProtectionStore
    from cyber_os.protection.triage import ProtectionTriage

    class Provider:
        available = True

        def __init__(self):
            self.calls = 0

        def analyze(self, context):
            self.calls += 1
            assert "file_path" not in context
            assert "sha256" not in context
            return "Rule analysis is complete."

        def respond(self, context, history, message):
            return "This alert matched a configured rule."

    store = ProtectionStore(tmp_path / "triage.db")
    store.record_detection(DetectionRecord(
        detection_id="det-triage", sha256="b" * 64, rule_id="hash-2", rule_version="rules-7",
        action="block", confidence="high", severity="high", file_type=".exe", size_bytes=2048,
        file_path=r"C:\Users\Alice\Downloads\payload.exe", created_at="2026-01-01T00:00:00",
        triage_enqueued=False,
    ))
    provider = Provider()
    triage = ProtectionTriage(store, provider)
    monkeypatch.setattr(server, "_get_protection_triage", lambda: triage, raising=False)

    with TestClient(server.app) as client:
        first = client.post("/api/protection/triage/det-triage")
        second = client.post("/api/protection/triage/det-triage")
        result = client.get("/api/protection/triage", params={"detection_id": "det-triage"})

    assert first.status_code == 200
    assert second.status_code == 200
    assert result.status_code == 200
    assert result.json()["triage_id"] == "det-triage"
    assert result.json()["state"] in {"queued", "running", "completed"}
    assert result.json()["recommendations"] == []
    assert store.count_triage_jobs() == 1
    assert store.get_detection("det-triage").action == "block"


def test_get_unknown_scan_job_returns_404(monkeypatch, mock_protection_service):
    _reset_protection_service_mock()
    mock_protection_service.store.get_scan_job.return_value = None
    monkeypatch.setattr(server, "_get_protection_service", lambda: mock_protection_service)

    with TestClient(server.app) as client:
        reply = client.get("/api/protection/scans/nonexistent-job")

    assert reply.status_code == 404


def test_cancel_unknown_scan_job_returns_404(monkeypatch, mock_protection_service):
    _reset_protection_service_mock()
    mock_protection_service.cancel_scan.return_value = False
    monkeypatch.setattr(server, "_get_protection_service", lambda: mock_protection_service)

    with TestClient(server.app) as client:
        reply = client.delete("/api/protection/scans/nonexistent-job")

    assert reply.status_code == 404


def test_unavailable_service_reports_unavailable_without_crashing(monkeypatch):
    """Real _UnavailableService fallback: honest unavailable + zeroed counts, no 500 crash.

    Forces the lazy ``from cyber_os.protection import ...`` to fail so
    ``_get_protection_service`` builds its real ``_UnavailableService`` fallback,
    then asserts the status, threats, and scan-job routes degrade gracefully
    (the store-scoped routes call ``service.store.<method>`` and must not raise
    AttributeError -> HTTP 500).
    """
    import sys

    # Block the protection package so the except-branch fallback is built.
    monkeypatch.setitem(sys.modules, "cyber_os.protection", None)
    monkeypatch.setattr(server, "_protection_service", None, raising=False)

    with TestClient(server.app) as client:
        status_reply = client.get("/api/protection/status")
        threats_reply = client.get("/api/protection/threats")
        scan_reply = client.get("/api/protection/scans/does-not-exist")

    assert status_reply.status_code == 200
    status = status_reply.json()
    assert status["state"] == "unavailable"
    assert status["counts"] == {"detected": 0, "blocked": 0, "quarantined": 0}
    assert status["last_error"]  # a real error string, not None

    # Store-scoped routes must degrade gracefully, not crash with AttributeError.
    assert threats_reply.status_code == 200
    assert threats_reply.json() == []
    assert scan_reply.status_code == 404
