from __future__ import annotations

from cyber_os.protection.models import RuleSet
from cyber_os.protection.service import ProtectionConfig, ProtectionService
from cyber_os.protection.store import ProtectionStore
from cyber_os.sensors.warnings import (
    SensorAnomalyRules,
    SensorResponseCoordinator,
    SensorWarningStore,
)
from cyber_os.sensors.windows_sensor_service import SensorEvent


def _failed_logon(event_id: str) -> SensorEvent:
    return SensorEvent(
        timestamp="2026-10-13T10:00:00Z",
        event_id=event_id,
        event_type="failed_logon",
        category="auth",
        severity="MEDIUM",
        source="Windows Security event 4625",
        details={"source_ip": "192.0.2.25", "target_user_hash": "account-hash"},
        sensor_ids=[130],
    )


def test_failed_login_anomaly_persists_redacted_warning_once(tmp_path):
    store = SensorWarningStore(str(tmp_path / "warnings.sqlite3"))
    coordinator = SensorResponseCoordinator(store, SensorAnomalyRules(failed_logons=2))

    coordinator.submit_event(_failed_logon("event-1"))
    coordinator.submit_event(_failed_logon("event-2"))
    coordinator.submit_event(_failed_logon("event-2"))

    warnings = coordinator.get_warnings()
    assert len(warnings) == 1
    assert warnings[0]["event_id"] == "event-2"
    assert warnings[0]["sensor_ids"] == [130]
    assert "192.0.2.25" not in str(warnings[0])
    assert warnings[0]["ai_state"] == "pending"


def test_sensor_event_serialization_never_persists_transient_file_target():
    event = _failed_logon("private-path-event")
    event._protection_target = "C:\\Users\\Alice\\Downloads\\sample.exe"

    assert "_protection_target" not in event.to_dict()
    assert "Downloads" not in str(event.to_dict())


def test_ai_escalation_uses_a_lease_and_persists_result(tmp_path):
    coordinator = SensorResponseCoordinator(
        SensorWarningStore(str(tmp_path / "warnings.sqlite3")),
        SensorAnomalyRules(failed_logons=2),
    )
    coordinator.submit_event(_failed_logon("event-1"))
    coordinator.submit_event(_failed_logon("event-2"))

    claimed = coordinator.claim_ai_escalations("api-worker", lease_seconds=30)
    assert [item["event_id"] for item in claimed] == ["event-2"]
    assert coordinator.claim_ai_escalations("other-worker") == []
    assert coordinator.complete_ai_escalation(
        "event-2", "api-worker", {"analysis": "Repeated failed logons require review."}
    )
    warning = coordinator.get_warnings()[0]
    assert warning["ai_state"] == "completed"
    assert warning["ai_analysis"] == "Repeated failed logons require review."


def test_high_confidence_ai_file_assessment_is_advisory_only(tmp_path):
    target = tmp_path / "installer.exe"
    target.write_bytes(b"unrecognized executable sample")
    protection_store = ProtectionStore(tmp_path / "protection.sqlite3")
    protection = ProtectionService(ProtectionConfig(
        quarantine_root=tmp_path / "quarantine",
        rules=RuleSet("empty-demo", ()),
        store=protection_store,
    ))
    coordinator = SensorResponseCoordinator(
        SensorWarningStore(str(tmp_path / "warnings.sqlite3")),
        SensorAnomalyRules(),
        protection_service=protection,
    )
    event = SensorEvent(
        timestamp="2026-10-13T10:00:00Z",
        event_id="file-event-1",
        event_type="file_activity",
        category="file",
        severity="INFO",
        source="Windows Security event 4663",
        details={"file_operation": "create_or_modify"},
        sensor_ids=[49, 50],
        _protection_target=str(target),
    )
    coordinator.submit_event(event)
    assert target.exists()
    warning = coordinator.get_warnings()[0]
    assert str(target) not in str(warning)
    claim = coordinator.claim_ai_escalations("test-worker")[0]

    unclaimed_result = {
        "analysis": "The observed executable is malicious.",
        "classification": "malicious",
        "confidence": 0.99,
        "recommended_action": "quarantine",
    }
    assert not coordinator.complete_ai_escalation(
        claim["event_id"], "unowned-worker", unclaimed_result
    )
    assert target.exists()
    assert len(protection.list_quarantine()) == 0

    assert coordinator.complete_ai_escalation(claim["event_id"], "test-worker", {
        "analysis": "The observed executable is malicious.",
        "classification": "malicious",
        "confidence": 0.99,
        "recommended_action": "quarantine",
    })

    updated = coordinator.get_warnings()[0]
    assert target.exists()
    assert updated["protection_state"] == "clean"
    assert updated["protection_action"] is None
    assert len(protection.list_quarantine()) == 0
