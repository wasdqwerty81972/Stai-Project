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
from cyber_os.protection.store import ProtectionStore

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
