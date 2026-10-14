"""The product must never claim protection it did not actually verify.

``/api/protection/status`` (ui/api_server.py) calls ``service.get_status()``
with no arguments, so whatever that call defaults to is what the dashboard
shows the user. ``ProtectionService.get_status`` previously defaulted
``service_state`` to ``"running"`` while ``ProtectionStore.get_status``
defaulted it to ``"unknown"`` -- so the API reported a running protection
service that nothing had probed.

These tests pin the invariant: an unprobed state is reported as unknown, and
only an explicitly supplied "running" for both the driver and the service may
produce an ``active`` state.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from cyber_os.protection.models import DetectionRule, RuleSet
from cyber_os.protection.service import ProtectionConfig, ProtectionService
from cyber_os.protection.store import DetectionRecord, ProtectionStore

_MARKER = b"STAI inert antivirus test marker"


def _service(tmp_path: Path) -> tuple[ProtectionService, ProtectionStore]:
    store = ProtectionStore(tmp_path / "p.db")
    rules = RuleSet(
        version="test-1",
        rules=(
            DetectionRule(
                id="hash-1",
                kind="sha256",
                value=hashlib.sha256(_MARKER).hexdigest(),
                action="block",
                confidence="high",
            ),
        ),
    )
    config = ProtectionConfig(quarantine_root=tmp_path / "quar", rules=rules, store=store)
    return ProtectionService(config), store


def test_unprobed_status_never_claims_a_running_service(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)

    status = service.get_status()

    # The caller supplied nothing, so nothing may be asserted as running.
    assert status.service_state == "unknown"
    assert status.driver_state == "unknown"
    assert status.state != "active"


def test_unprobed_status_matches_the_store_default(tmp_path: Path) -> None:
    # The service layer must not be more optimistic than the store it wraps.
    service, store = _service(tmp_path)

    assert service.get_status().service_state == store.get_status().service_state


def test_active_requires_both_states_to_be_explicitly_running(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)

    assert service.get_status(driver_state="running").state != "active"
    assert service.get_status(service_state="running").state != "active"
    assert (
        service.get_status(driver_state="running", service_state="running").state
        == "active"
    )


def test_a_stopped_driver_is_reported_not_hidden(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)

    status = service.get_status(driver_state="stopped", service_state="running")

    assert status.driver_state == "stopped"
    assert status.state != "active"


def test_quarantine_detection_is_not_capped_by_a_listing_page(tmp_path: Path) -> None:
    """A detection outside the first list_threats() page must stay actionable.

    quarantine_detection() used to page through list_threats(limit=1000) and
    linear-search it, so any detection beyond that page reported "detection not
    found" and could never be quarantined. It now looks the record up directly.
    """
    service, store = _service(tmp_path)

    page_size = 1000
    target_id = "detection-beyond-the-page"
    for index in range(page_size + 1):
        detection_id = target_id if index == 0 else f"detection-{index}"
        store.record_detection(
            DetectionRecord(
                detection_id=detection_id,
                sha256=hashlib.sha256(f"{index}".encode()).hexdigest(),
                rule_id="hash-1",
                rule_version="test-1",
                action="block",
                confidence="high",
                severity="critical",
                file_type=".exe",
                size_bytes=len(_MARKER),
                file_path=str(tmp_path / f"sample-{index}.exe"),
                created_at=f"2026-10-14T09:{index // 60:02d}:{index % 60:02d}.000000",
                triage_enqueued=False,
            )
        )

    # The oldest detection is off the end of the first page. The file does not
    # exist, so quarantine must still fail -- but it must fail for the honest
    # reason, not because the lookup could not see the record at all.
    result = service.quarantine_detection(target_id)

    assert result.success is False
    assert result.error != "detection not found"
