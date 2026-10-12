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
import threading
from datetime import datetime
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
    result = svc.quarantine_detection(detection.detection_id)

    assert result.success is True
    assert store.get_status().counts == {"detected": 1, "blocked": 0, "quarantined": 1}
    assert not sample.exists()  # moved out of its original location
    assert result.item is not None and Path(result.item.quarantined_path).exists()


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
    svc.scan_file(sample)
    detection = store.list_threats()[0]

    def _boom(src: Path, dst: Path) -> None:
        raise OSError("simulated move failure")

    monkeypatch.setattr(quarantine_mod, "_atomic_move", _boom)

    result = svc.quarantine_detection(detection.detection_id)

    assert result.success is False
    assert store.get_status().counts["quarantined"] == 0
    assert sample.exists()  # original preserved when the move fails


def test_restore_rescans_and_refuses_detected_file(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_MARKER)
    svc, store = _service(tmp_path, _block_ruleset(_MARKER))
    svc.scan_file(sample)
    detection = store.list_threats()[0]
    quarantined = svc.quarantine_detection(detection.detection_id)
    assert quarantined.success is True
    item_id = quarantined.item.item_id

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


def test_iter_files_reports_inaccessible_descendants(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    svc, _store = _service(tmp_path, RuleSet("test-1", ()))
    errors: list[OSError] = []

    def inaccessible_walk(_root, *, topdown, followlinks, onerror):
        assert topdown is True and followlinks is False
        onerror(PermissionError(13, "permission denied", str(root / "private")))
        yield str(root), [], []

    monkeypatch.setattr(service_mod.os, "walk", inaccessible_walk)

    assert list(svc._iter_files(root, on_error=errors.append)) == []
    assert len(errors) == 1
    assert isinstance(errors[0], PermissionError)


def test_quick_scan_deduplicates_overlapping_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    outer = tmp_path / "user"
    nested = outer / "Downloads"
    startup = tmp_path / "startup"
    nested.mkdir(parents=True)
    startup.mkdir()
    outer_file = outer / "document.txt"
    nested_file = nested / "download.txt"
    startup_file = startup / "startup.txt"
    for path in (outer_file, nested_file, startup_file):
        path.write_text("clean", encoding="utf-8")
    roots = (("desktop", str(outer)), ("downloads", str(nested)), ("startup", str(startup)))
    svc, store = _service(tmp_path, RuleSet("test-1", ()))
    observed: list[Path] = []
    monkeypatch.setattr(
        svc,
        "scan_file",
        lambda path: observed.append(path) or ScanVerdict(
            status="clean", action="allow", rule_id=None, rule_version="test-1", sha256=None, reason="clean"
        ),
    )

    job = svc.start_scan("quick", roots=roots)
    assert svc._scan_thread is not None
    svc._scan_thread.join(timeout=5)

    assert sorted(path.resolve() for path in observed) == sorted(
        (outer_file.resolve(), nested_file.resolve(), startup_file.resolve())
    )
    coverage = {item["folder_id"]: item["status"] for item in store.get_scan_job_root_coverage(job.job_id)}
    assert coverage == {"desktop": "scanned", "downloads": "covered", "startup": "scanned"}


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
    found = {Path(p).resolve() for p in svc._iter_files(root)}

    assert secret.resolve() not in found, "scan followed a symlink outside the scope"


def test_quick_scan_requires_explicit_enrolled_roots(tmp_path: Path) -> None:
    svc, _store = _service(tmp_path, RuleSet("test-1", ()))

    with pytest.raises(RuntimeError, match="profile"):
        svc.start_scan("quick")


def test_quick_scan_worker_uses_job_snapshot_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "enrolled" / "Desktop"
    root.mkdir(parents=True)
    sample = root / "user.txt"
    sample.write_text("in scope", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("out of scope", encoding="utf-8")
    roots = (
        ("desktop", str(root)),
        ("downloads", str(tmp_path / "missing-downloads")),
        ("startup", str(tmp_path / "missing-startup")),
    )
    svc, store = _service(tmp_path, RuleSet("test-1", ()))
    scanned: list[Path] = []
    monkeypatch.setattr(svc, "scan_file", lambda path: scanned.append(path) or ScanVerdict(
        status="clean", action="allow", rule_id=None, rule_version="test-1", sha256=None, reason="clean"
    ))

    job = svc.start_scan("quick", roots=roots)
    assert svc._scan_thread is not None
    svc._scan_thread.join(timeout=5)

    final = store.get_scan_job(job.job_id)
    assert final is not None and final.state == "completed"
    assert final.errors == 2
    assert scanned == [sample]


def test_quick_scan_fails_when_no_snapshot_root_is_usable(tmp_path: Path) -> None:
    roots = (
        ("desktop", str(tmp_path / "missing-desktop")),
        ("downloads", str(tmp_path / "missing-downloads")),
        ("startup", str(tmp_path / "missing-startup")),
    )
    svc, store = _service(tmp_path, RuleSet("test-1", ()))

    job = svc.start_scan("quick", roots=roots)
    assert svc._scan_thread is not None
    svc._scan_thread.join(timeout=5)

    final = store.get_scan_job(job.job_id)
    assert final is not None and final.state == "failed"
    assert final.errors == 3
    assert "usable" in (final.error_message or "")


def test_refresh_scan_profile_persists_only_resolved_known_folders(tmp_path: Path) -> None:
    roots = (
        ("desktop", r"D:\Redirected\Desktop"),
        ("downloads", r"D:\Redirected\Downloads"),
        ("startup", r"C:\Users\Alice\Startup"),
    )
    svc, store = _service(tmp_path, RuleSet("test-1", ()))
    svc._profile_resolver = type("Resolver", (), {"resolve": lambda _self, _token: roots})()

    profile = svc.refresh_scan_profile("S-1-5-21-1-2-3-1001", object())

    assert profile.roots == roots
    assert store.get_scan_profile(profile.owner_sid) == profile


def test_scheduled_scan_claim_uses_saved_profile_without_resolving_user_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "enrolled" / "Desktop"
    root.mkdir(parents=True)
    (root / "sample.txt").write_text("scan me", encoding="utf-8")
    roots = (
        ("desktop", str(root)),
        ("downloads", str(tmp_path / "offline-downloads")),
        ("startup", str(tmp_path / "offline-startup")),
    )
    sid = "S-1-5-21-1-2-3-1001"
    svc, store = _service(tmp_path, RuleSet("test-1", ()))
    store.replace_scan_profile(sid, roots, "2026-10-12T09:00:00")
    store.set_scan_schedule(
        sid, enabled=True, cadence="daily", local_time="10:00", days_of_week=(),
        now_local=datetime(2026, 10, 12, 9, 0),
    )
    observed: list[Path] = []
    monkeypatch.setattr(svc, "scan_file", lambda path: observed.append(path) or ScanVerdict(
        status="clean", action="allow", rule_id=None, rule_version="test-1", sha256=None, reason="clean"
    ))
    job = svc.run_due_scheduled_scan(sid, now_local=datetime(2026, 10, 12, 10, 5))
    assert job is not None and job.source == "schedule"
    assert svc._scan_thread is not None
    svc._scan_thread.join(timeout=5)
    final = store.get_scan_job(job.job_id)
    assert final is not None and final.state == "completed" and final.errors == 2
    assert observed == [root / "sample.txt"]


def test_running_scan_can_be_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan_root = tmp_path / "scanroot"
    scan_root.mkdir()
    files = [scan_root / f"f{i}.bin" for i in range(3)]
    for f in files:
        f.write_bytes(b"x")

    svc, store = _service(tmp_path, RuleSet("test-1", ()))
    roots = (
        ("desktop", str(scan_root)),
        ("downloads", str(tmp_path / "downloads")),
        ("startup", str(tmp_path / "startup")),
    )

    def _fake_iter(self, root, **_kwargs):  # noqa: ANN001 - test stub
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

    job = svc.start_scan("quick", roots=roots)
    assert svc._scan_thread is not None
    svc._scan_thread.join(timeout=5)

    final = store.get_scan_job(job.job_id)
    assert final is not None
    assert final.state == "cancelled"


def test_scheduled_worker_start_failure_is_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sid = "S-1-5-21-1-2-3-1001"
    roots = (
        ("desktop", r"C:\Users\alice\Desktop"),
        ("downloads", r"C:\Users\alice\Downloads"),
        ("startup", r"C:\Users\alice\Startup"),
    )
    svc, store = _service(tmp_path, RuleSet("test-1", ()))
    store.replace_scan_profile(sid, roots, "2026-10-12T09:00:00")
    store.set_scan_schedule(
        sid, enabled=True, cadence="daily", local_time="10:00", days_of_week=(),
        now_local=datetime(2026, 10, 12, 9, 0),
    )
    monkeypatch.setattr(threading.Thread, "start", lambda _self: (_ for _ in ()).throw(RuntimeError("thread failure")))

    assert svc.run_due_scheduled_scan(sid, now_local=datetime(2026, 10, 12, 10, 5)) is None

    schedule = store.get_scan_schedule(sid)
    assert schedule is not None and schedule.last_result == "failed"
    assert store.get_scan_job(schedule.last_job_id).state == "failed"


def test_shutdown_gate_prevents_scheduled_occurrence_claim(tmp_path: Path) -> None:
    sid = "S-1-5-21-1-2-3-1001"
    roots = (
        ("desktop", r"C:\Users\alice\Desktop"),
        ("downloads", r"C:\Users\alice\Downloads"),
        ("startup", r"C:\Users\alice\Startup"),
    )
    svc, store = _service(tmp_path, RuleSet("test-1", ()))
    store.replace_scan_profile(sid, roots, "2026-10-12T09:00:00")
    store.set_scan_schedule(
        sid, enabled=True, cadence="daily", local_time="10:00", days_of_week=(),
        now_local=datetime(2026, 10, 12, 9, 0),
    )
    svc.stop_scheduled_scans()

    assert svc.run_due_scheduled_scan(sid, now_local=datetime(2026, 10, 12, 10, 5)) is None

    schedule = store.get_scan_schedule(sid)
    assert schedule is not None and schedule.last_job_id is None
