"""Service-level tests for the Windows protection core (plan Task 3).

Covers the durable outcome invariants that the ``ProtectionService`` layer
must enforce on top of the store:

* quarantine increments only after a verified move; a failed move does not;
* restore rescans and refuses a file that still matches a block rule;
* scanning stays inside scope (quarantine dir excluded; symlinks not followed);
* a running scan can be cancelled and ends in a durable ``cancelled`` state.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cyber_os.protection import quarantine as quarantine_mod
from cyber_os.protection import service as service_mod
from cyber_os.protection.models import DetectionRule, RuleSet, ScanVerdict
from cyber_os.protection.service import ProtectionConfig, ProtectionService
from cyber_os.protection.store import IndicatorRecord, ProtectionStore, ThreatIntelStore

_MARKER = b"STAI inert antivirus test marker"


def _block_ruleset(content: bytes) -> RuleSet:
    return RuleSet(
        version="test-1",
        rules=(
            DetectionRule(
                id="hash-1",
                kind="sha256",
                value=hashlib.sha256(content).hexdigest(),
                action="block",
                confidence="high",
            ),
        ),
    )


def _service(tmp_path: Path, rules: RuleSet, *, quarantine_root: Path | None = None):
    store = ProtectionStore(tmp_path / "p.db")
    config = ProtectionConfig(
        quarantine_root=quarantine_root or (tmp_path / "quar"),
        rules=rules,
        store=store,
    )
    return ProtectionService(config), store


def test_quarantine_count_requires_verified_move(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_MARKER)
    svc, store = _service(tmp_path, _block_ruleset(_MARKER))

    verdict = svc.scan_file(sample)
    assert (verdict.status, verdict.action) == ("detected", "block")

    detection = store.list_threats()[0]
    items = svc.list_quarantine()

    assert len(items) == 1
    assert store.get_status().counts == {"detected": 1, "blocked": 0, "quarantined": 1}
    assert not sample.exists()  # moved out of its original location
    assert Path(items[0].quarantined_path).exists()


def test_detection_callback_runs_after_detection_is_durable(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_MARKER)
    store = ProtectionStore(tmp_path / "p.db")
    observed: list[str] = []

    def on_detection(detection_id: str) -> None:
        assert store.get_detection(detection_id) is not None
        observed.append(detection_id)

    service = ProtectionService(
        ProtectionConfig(
            quarantine_root=tmp_path / "quar",
            rules=_block_ruleset(_MARKER),
            store=store,
        ),
        on_detection=on_detection,
    )

    verdict, detection_id = service.scan_file_for_filter(sample)

    assert verdict.status == "detected"
    assert detection_id is not None
    assert observed == [detection_id]


def test_exact_hash_intel_is_durable_advisory_evidence(tmp_path: Path) -> None:
    sample = tmp_path / "reported.exe"
    sample.write_bytes(b"reported sample")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    store = ProtectionStore(tmp_path / "protection.db")
    intel = ThreatIntelStore(tmp_path / "intel.db")
    now = "2026-10-14T12:00:00"
    intel.upsert_indicators(
        [
            IndicatorRecord(
                indicator_type="sha256",
                indicator_value=digest,
                source="abusech_malwarebazaar",
                confidence=95,
                severity="high",
                verification="confirmed",
                feed_version="mb-2026-10-14",
                first_seen=now,
                last_seen=now,
                sha256=digest,
                threat_family="test-family",
            )
        ],
        feed_version="mb-2026-10-14",
    )
    service = ProtectionService(
        ProtectionConfig(
            quarantine_root=tmp_path / "quar",
            rules=RuleSet("signed-1", ()),
            store=store,
            threat_intel_store=intel,
        )
    )

    verdict, detection_id = service.scan_file_for_filter(sample)

    assert verdict.status == "clean"
    assert verdict.action == "allow"
    assert verdict.intel_evidence is not None
    assert verdict.intel_evidence.indicator_value == digest
    assert verdict.intel_evidence.verification == "confirmed"
    assert verdict.intel_evidence.freshness in {"fresh", "aging"}
    assert detection_id is not None
    evidence_record = store.get_detection(detection_id)
    assert evidence_record is not None
    assert evidence_record.action == "allow"
    assert evidence_record.intel_evidence == verdict.intel_evidence
    assert store.get_status().counts == {"detected": 1, "blocked": 0, "quarantined": 0}


def test_repeated_scans_preserve_exact_hash_evidence(tmp_path: Path) -> None:
    sample = tmp_path / "repeat.exe"
    sample.write_bytes(b"repeat sample")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    intel = ThreatIntelStore(tmp_path / "intel.db")
    now = "2026-10-14T12:00:00"
    intel.upsert_indicators([IndicatorRecord(
        indicator_type="sha256", indicator_value=digest, source="abusech_malwarebazaar",
        confidence=95, severity="high", verification="confirmed", feed_version="feed-1",
        first_seen=now, last_seen=now, sha256=digest,
    )], feed_version="feed-1")
    store = ProtectionStore(tmp_path / "protection.db")
    service = ProtectionService(ProtectionConfig(
        quarantine_root=tmp_path / "quar", rules=RuleSet("rules-1", ()), store=store,
        threat_intel_store=intel,
    ))

    first_verdict, first_id = service.scan_file_for_filter(sample)
    second_verdict, second_id = service.scan_file_for_filter(sample)

    assert first_id and second_id and first_id != second_id
    assert first_verdict.intel_evidence == second_verdict.intel_evidence
    assert store.get_detection(first_id).intel_evidence == store.get_detection(second_id).intel_evidence


def test_intel_evidence_does_not_change_unknown_scanner_outcome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sample = tmp_path / "unknown.exe"
    sample.write_bytes(b"unknown result")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    intel = ThreatIntelStore(tmp_path / "intel.db")
    now = "2026-10-14T12:00:00"
    intel.upsert_indicators([IndicatorRecord(
        indicator_type="sha256", indicator_value=digest, source="abusech_malwarebazaar",
        confidence=95, severity="high", verification="confirmed", feed_version="feed-1",
        first_seen=now, last_seen=now, sha256=digest,
    )], feed_version="feed-1")
    monkeypatch.setattr(service_mod, "scan_path", lambda *_args, **_kwargs: ScanVerdict(
        status="unknown", action="allow", rule_id=None, rule_version="rules-1",
        sha256=digest, reason="YARA unavailable", reason_code="analysis_unavailable",
    ))
    service = ProtectionService(ProtectionConfig(
        quarantine_root=tmp_path / "quar", rules=RuleSet("rules-1", ()),
        store=ProtectionStore(tmp_path / "protection.db"), threat_intel_store=intel,
    ))

    verdict, detection_id = service.scan_file_for_filter(sample)

    assert verdict.status == "unknown" and verdict.action == "allow"
    assert verdict.intel_evidence is not None
    assert detection_id is not None


def test_network_ioc_never_becomes_file_scan_evidence(tmp_path: Path) -> None:
    sample = tmp_path / "clean.exe"
    sample.write_bytes(b"ordinary file")
    intel = ThreatIntelStore(tmp_path / "intel.db")
    intel.upsert_indicators([IndicatorRecord(
        indicator_type="domain", indicator_value="malicious.example", source="abusech_threatfox",
        confidence=50, severity="high", verification="reported", feed_version="feed-1",
        first_seen="2026-10-14T12:00:00", last_seen="2026-10-14T12:00:00",
    )], feed_version="feed-1")
    service = ProtectionService(ProtectionConfig(
        quarantine_root=tmp_path / "quar", rules=RuleSet("rules-1", ()),
        store=ProtectionStore(tmp_path / "protection.db"), threat_intel_store=intel,
    ))

    verdict, detection_id = service.scan_file_for_filter(sample)

    assert verdict.status == "clean" and verdict.action == "allow"
    assert verdict.intel_evidence is None
    assert detection_id is None


def test_intel_evidence_never_overrides_signed_block_verdict(tmp_path: Path) -> None:
    sample = tmp_path / "signed-match.exe"
    sample.write_bytes(_MARKER)
    digest = hashlib.sha256(_MARKER).hexdigest()
    store = ProtectionStore(tmp_path / "protection.db")
    intel = ThreatIntelStore(tmp_path / "intel.db")
    now = "2026-10-14T12:00:00"
    intel.upsert_indicators(
        [
            IndicatorRecord(
                indicator_type="sha256",
                indicator_value=digest,
                source="abusech_malwarebazaar",
                confidence=95,
                severity="high",
                verification="confirmed",
                feed_version="mb-2026-10-14",
                first_seen=now,
                last_seen=now,
                sha256=digest,
            )
        ],
        feed_version="mb-2026-10-14",
    )
    service = ProtectionService(
        ProtectionConfig(
            quarantine_root=tmp_path / "quar",
            rules=_block_ruleset(_MARKER),
            store=store,
            threat_intel_store=intel,
        )
    )

    verdict, detection_id = service.scan_file_for_filter(sample)

    assert (verdict.status, verdict.action, verdict.rule_id) == ("detected", "block", "hash-1")
    assert verdict.intel_evidence is not None
    assert detection_id is not None
    assert store.get_detection(detection_id).action == "block"


def test_threat_intel_health_is_advisory_and_reports_corruption(tmp_path: Path) -> None:
    empty_store = ThreatIntelStore(tmp_path / "empty-intel.db")
    empty_service = ProtectionService(ProtectionConfig(
        quarantine_root=tmp_path / "quar", rules=RuleSet("rules-1", ()),
        store=ProtectionStore(tmp_path / "empty-protection.db"), threat_intel_store=empty_store,
    ))
    assert empty_service.threat_intel_status() == {
        "state": "advisory", "integrity_ok": True, "block_eligible_records": 0, "activation": "inactive",
    }

    corrupt_path = tmp_path / "corrupt-intel.db"
    corrupt_path.write_bytes(b"not a sqlite database")
    corrupt_store = ThreatIntelStore(corrupt_path)
    corrupt_service = ProtectionService(ProtectionConfig(
        quarantine_root=tmp_path / "quar", rules=RuleSet("rules-1", ()),
        store=ProtectionStore(tmp_path / "corrupt-protection.db"), threat_intel_store=corrupt_store,
    ))
    assert corrupt_service.threat_intel_status()["state"] == "degraded"
    assert corrupt_service.threat_intel_status()["integrity_ok"] is False

    sample = tmp_path / "signed-rule-match.exe"
    sample.write_bytes(_MARKER)
    protected_scan = ProtectionService(ProtectionConfig(
        quarantine_root=tmp_path / "quar", rules=_block_ruleset(_MARKER),
        store=ProtectionStore(tmp_path / "protection-with-corrupt-intel.db"),
        threat_intel_store=corrupt_store,
    ))
    verdict, _detection_id = protected_scan.scan_file_for_filter(sample)
    assert (verdict.status, verdict.action, verdict.rule_id) == ("detected", "block", "hash-1")

def test_detection_callback_failure_does_not_change_scan_verdict(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_MARKER)
    service, _store = _service(tmp_path, _block_ruleset(_MARKER))

    service._on_detection = lambda _detection_id: (_ for _ in ()).throw(RuntimeError("triage offline"))
    verdict, detection_id = service.scan_file_for_filter(sample)

    assert verdict.status == "detected" and verdict.action == "block"
    assert detection_id is not None


def test_filter_quarantine_reuses_detection_and_verifies_file_hash(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_MARKER)
    service, store = _service(tmp_path, _block_ruleset(_MARKER))

    verdict, detection_id = service.scan_file_for_filter(sample)
    assert detection_id is not None
    result = service.quarantine_scanned_detection(detection_id, sample, verdict)

    assert result.success is True
    assert store.get_status().counts == {"detected": 1, "blocked": 0, "quarantined": 1}
    assert store.get_detection(detection_id) is not None
    assert not sample.exists()


def test_filter_quarantine_rejects_verdict_not_bound_to_detection(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_MARKER)
    service, store = _service(tmp_path, _block_ruleset(_MARKER))
    verdict, detection_id = service.scan_file_for_filter(sample)
    assert detection_id is not None
    mismatched = ScanVerdict(
        status=verdict.status,
        action=verdict.action,
        rule_id=verdict.rule_id,
        rule_version=verdict.rule_version,
        sha256="0" * 64,
        reason=verdict.reason,
    )

    result = service.quarantine_scanned_detection(detection_id, sample, mismatched)

    assert result.success is False
    assert sample.exists()
    assert store.get_status().counts["quarantined"] == 0


def test_failed_move_does_not_count_as_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_MARKER)
    svc, store = _service(tmp_path, _block_ruleset(_MARKER))
    def _boom(src: Path, dst: Path) -> None:
        raise OSError("simulated move failure")

    monkeypatch.setattr(quarantine_mod, "_atomic_move", _boom)

    svc.scan_file(sample)
    detection = store.list_threats()[0]

    result = svc.quarantine_detection(detection.detection_id)

    assert result.success is False
    assert store.get_status().counts["quarantined"] == 0
    assert sample.exists()  # original preserved when the move fails


def test_restore_rescans_and_refuses_detected_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_MARKER)
    svc, store = _service(tmp_path, _block_ruleset(_MARKER))
    svc.scan_file(sample)
    quarantined = svc.list_quarantine()
    assert len(quarantined) == 1
    item_id = quarantined[0].item_id

    # The ruleset still flags the content as a high-confidence block, so a
    # restore must rescan and refuse (never re-expose malware).
    result = svc.restore_quarantine(item_id)

    assert result.success is False
    assert "refus" in (result.error or "").lower() or "block" in (result.error or "").lower()
    assert not sample.exists()  # original NOT re-created
    items = svc.list_quarantine()
    assert items[0].restore_result == "refused"


def test_iter_files_excludes_quarantine_directory(tmp_path: Path) -> None:
    root = tmp_path / "scanroot"
    root.mkdir()
    normal = root / "a.txt"
    normal.write_text("ordinary content", encoding="utf-8")
    quarantine_root = root / "quar"
    quarantine_root.mkdir()
    (quarantine_root / "held.bin").write_bytes(b"quarantined")

    svc, _ = _service(tmp_path, RuleSet("test-1", ()), quarantine_root=quarantine_root)

    found = {Path(p).resolve() for p in svc._iter_files(root)}

    assert normal.resolve() in found
    assert (quarantine_root / "held.bin").resolve() not in found


def test_scan_does_not_follow_symlink_outside_scope(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.bin"
    secret.write_bytes(b"must-not-be-scanned")
    root = tmp_path / "scanroot"
    root.mkdir()
    (root / "normal.txt").write_text("x", encoding="utf-8")

    link = root / "link_to_outside"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating a directory symlink is not permitted on this host")

    svc, _ = _service(tmp_path, RuleSet("test-1", ()))
    skipped: list[int] = []
    found = {
        Path(p).resolve()
        for p in svc._iter_files(root, on_skip=lambda: skipped.append(1))
    }

    assert secret.resolve() not in found, "scan followed a symlink outside the scope"
    assert skipped == [1]


def test_scan_walk_reports_inaccessible_roots(tmp_path: Path) -> None:
    svc, _ = _service(tmp_path, RuleSet("test-1", ()))
    errors: list[OSError] = []

    assert list(svc._iter_files(tmp_path / "missing", on_error=errors.append)) == []
    assert len(errors) == 1


def test_running_scan_can_be_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_root = tmp_path / "scanroot"
    scan_root.mkdir()
    files = [scan_root / f"f{i}.bin" for i in range(3)]
    for f in files:
        f.write_bytes(b"x")

    svc, store = _service(tmp_path, RuleSet("test-1", ()))
    monkeypatch.setattr(service_mod, "SCAN_ROOTS_QUICK", [scan_root])

    def _fake_iter(self, root, **_callbacks):  # noqa: ANN001 - test stub
        yield from files

    def _cancel_on_scan(self, path):  # noqa: ANN001 - test stub
        # Request cancellation as soon as the first file is scanned; the loop's
        # top-of-iteration check then stops the scan deterministically.
        self._cancel_scan.set()
        return ScanVerdict(
            status="clean", action="allow", rule_id=None, rule_version="test-1", sha256=None, reason="stub"
        )

    monkeypatch.setattr(ProtectionService, "_iter_files", _fake_iter)
    monkeypatch.setattr(ProtectionService, "scan_file", _cancel_on_scan)

    job = svc.start_scan("quick")
    assert svc._scan_thread is not None
    svc._scan_thread.join(timeout=5)

    final = store.get_scan_job(job.job_id)
    assert final is not None
    assert final.state == "cancelled"


def test_scan_with_unknown_verdict_is_persisted_as_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_root = tmp_path / "scanroot"
    scan_root.mkdir()
    (scan_root / "unreadable-by-engine.bin").write_bytes(b"uncertain")
    svc, store = _service(tmp_path, RuleSet("test-1", ()))
    monkeypatch.setattr(service_mod, "SCAN_ROOTS_QUICK", [scan_root])
    monkeypatch.setattr(
        ProtectionService,
        "scan_file",
        lambda self, _path: ScanVerdict(
            status="unknown",
            action="allow",
            rule_id=None,
            rule_version="test-1",
            sha256=None,
            reason="matcher unavailable",
        ),
    )

    job = svc.start_scan("quick")
    assert svc._scan_thread is not None
    svc._scan_thread.join(timeout=5)

    final = store.get_scan_job(job.job_id)
    assert final is not None
    assert final.state == "partial"
    assert final.files_scanned == 1
    assert final.unknown_verdicts == 1


def test_quick_scan_uses_configured_enrolled_user_roots_and_persists_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enrolled_root = tmp_path / "enrolled" / "Downloads"
    service_account_root = tmp_path / "service-account" / "Downloads"
    enrolled_root.mkdir(parents=True)
    service_account_root.mkdir(parents=True)
    (enrolled_root / "sample.bin").write_bytes(b"enrolled")
    (enrolled_root / "uncertain.bin").write_bytes(b"unknown")
    (service_account_root / "ignored.bin").write_bytes(b"wrong profile")

    svc, store = _service(tmp_path, RuleSet("test-1", ()))
    svc._config.quick_scan_roots = [enrolled_root]
    monkeypatch.setattr(service_mod, "SCAN_ROOTS_QUICK", [service_account_root])
    visited: list[Path] = []

    def _iter_configured(self, root, **_callbacks):  # noqa: ANN001 - test stub
        visited.append(Path(root))
        yield from root.iterdir()

    def _scan_fixture(self, path):  # noqa: ANN001 - test stub
        status = "unknown" if path.name == "uncertain.bin" else "clean"
        return ScanVerdict(
            status=status,
            action="allow",
            rule_id=None,
            rule_version="test-1",
            sha256=None,
            reason="fixture",
        )

    monkeypatch.setattr(ProtectionService, "_iter_files", _iter_configured)
    monkeypatch.setattr(ProtectionService, "scan_file", _scan_fixture)
    job = svc.start_scan("quick")
    assert svc._scan_thread is not None
    svc._scan_thread.join(timeout=5)

    final = store.get_scan_job(job.job_id)
    assert final is not None
    assert visited == [enrolled_root.resolve()]
    assert final.root_snapshot == [str(enrolled_root.resolve())]
    assert (final.files_total, final.files_scanned, final.unknown_verdicts) == (2, 2, 1)
    assert final.files_skipped == 0
    assert (final.engine_version, final.rules_version) == ("1", "test-1")
    assert final.duration_ms is not None and final.duration_ms >= 0
