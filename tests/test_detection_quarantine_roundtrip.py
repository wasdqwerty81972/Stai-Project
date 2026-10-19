"""Real quarantine, containment, and restore behaviour against a live store.

These tests use the on-disk ProtectionStore and the real filesystem. Nothing
here is mocked: files are hashed, moved, launched, and restored for real.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cyber_os.protection.models import DetectionRule, RuleSet, ScanVerdict
from cyber_os.protection.quarantine import (
    QUARANTINE_SUFFIX,
    list_quarantine_items,
    quarantine_file,
    restore_quarantine,
)
from cyber_os.protection.scanner import scan_path
from cyber_os.protection.store import DetectionRecord, ProtectionStore

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
_MARKER = "STAI_QUARANTINE_EXEC_MARKER"


def _store(tmp_path: Path) -> ProtectionStore:
    return ProtectionStore(tmp_path / "protection.db")


def _hash_rule(content: bytes, *, action: str = "block", confidence: str = "high") -> DetectionRule:
    return DetectionRule(
        id="test-hash-rule",
        kind="sha256",
        value=hashlib.sha256(content).hexdigest(),
        action=action,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
    )


def _record_detection(store: ProtectionStore, detection_id: str, verdict: ScanVerdict, path: Path) -> None:
    store.record_detection(DetectionRecord(
        detection_id=detection_id,
        sha256=verdict.sha256 or "",
        rule_id=verdict.rule_id or "unknown",
        rule_version=verdict.rule_version,
        action="block",
        confidence="high",
        severity="critical",
        file_type=path.suffix.lower() or None,
        size_bytes=path.stat().st_size,
        file_path=str(path),
        created_at="2026-10-14T00:00:00",
        triage_enqueued=False,
    ))


def test_quarantine_contains_then_restores_bytes_exactly(tmp_path: Path) -> None:
    """Quarantine a real executable batch file, prove it cannot run, restore it."""
    store = _store(tmp_path)
    quarantine_root = tmp_path / "quarantine"
    sample = tmp_path / "sample.cmd"
    content = f"@echo off\r\necho {_MARKER}\r\n".encode()
    sample.write_bytes(content)
    original_mtime_ns = sample.stat().st_mtime_ns

    # The file really executes before quarantine, so the post-quarantine
    # failure below is containment and not a broken fixture.
    if os.name == "nt":
        before = subprocess.run(
            ["cmd", "/c", str(sample)], capture_output=True, text=True, timeout=30
        )
        assert _MARKER in before.stdout, f"fixture never ran: {before.stdout!r} {before.stderr!r}"

    rules = RuleSet(version="test-1", rules=(_hash_rule(content),))
    verdict = scan_path(sample, rules)
    assert (verdict.status, verdict.action) == ("detected", "block"), verdict.reason

    detection_id = "det-roundtrip-1"
    _record_detection(store, detection_id, verdict, sample)

    result = quarantine_file(store, detection_id, sample, quarantine_root, verdict)
    assert result.success, result.error
    assert result.item is not None
    quarantined = Path(result.item.quarantined_path)

    # Contained: gone from its original location, present in quarantine under a
    # name with no executable extension.
    assert not sample.exists()
    assert quarantined.exists()
    assert quarantined.suffix == QUARANTINE_SUFFIX
    assert quarantined.read_bytes() == content

    # Cannot be executed in place.
    if os.name == "nt":
        shell = subprocess.run(
            ["cmd", "/c", str(quarantined)], capture_output=True, text=True, timeout=30
        )
        assert _MARKER not in shell.stdout, "quarantined file still ran via the shell"
        assert shell.returncode != 0

        direct = subprocess.run(
            ["icacls", str(quarantined)], capture_output=True, text=True, timeout=30
        )
        assert "(DENY)" in direct.stdout.upper() or "(N)" in direct.stdout.upper(), (
            f"expected a deny-execute ACE on the quarantined file: {direct.stdout!r}"
        )

        with pytest.raises(OSError):
            subprocess.run([str(quarantined)], capture_output=True, timeout=30)

    # Integrity is recorded and listable.
    items = list_quarantine_items(store)
    assert [item.item_id for item in items] == [result.item.item_id]
    assert items[0].sha256 == hashlib.sha256(content).hexdigest()

    restored = restore_quarantine(store, result.item.item_id, quarantine_root)
    assert restored.success, restored.error

    # Bytes round-trip exactly, and the move preserved the modification time.
    assert sample.exists()
    assert sample.read_bytes() == content
    assert hashlib.sha256(sample.read_bytes()).hexdigest() == verdict.sha256
    assert sample.stat().st_mtime_ns == original_mtime_ns
    assert not quarantined.exists()
    assert list_quarantine_items(store)[0].restore_result == "restored"

    # Usable again after restore.
    if os.name == "nt":
        after = subprocess.run(
            ["cmd", "/c", str(sample)], capture_output=True, text=True, timeout=30
        )
        assert _MARKER in after.stdout, f"restored file will not run: {after.stderr!r}"


def test_quarantine_refuses_observe_only_low_confidence_match(tmp_path: Path) -> None:
    """A non-blocking heuristic match must never be able to move a file."""
    store = _store(tmp_path)
    content = b"benign file that merely matches an observe rule"
    sample = tmp_path / "benign.dll"
    sample.write_bytes(content)

    rules = RuleSet(
        version="test-1",
        rules=(_hash_rule(content, action="observe", confidence="low"),),
    )
    verdict = scan_path(sample, rules)
    # The scanner reports the match but never escalates it to a block.
    assert (verdict.status, verdict.action) == ("detected", "allow")

    detection_id = "det-observe-1"
    _record_detection(store, detection_id, verdict, sample)

    result = quarantine_file(store, detection_id, sample, tmp_path / "quarantine", verdict)

    assert not result.success
    assert "not a verified block detection" in (result.error or "")
    assert sample.exists()
    assert sample.read_bytes() == content
    assert list_quarantine_items(store) == []


def test_quarantine_refuses_verdict_without_verified_hash(tmp_path: Path) -> None:
    """A verdict carrying no hash must not bypass the integrity check."""
    store = _store(tmp_path)
    sample = tmp_path / "unverified.bin"
    sample.write_bytes(b"no hash was ever verified for this file")

    verdict = ScanVerdict(
        status="detected",
        action="block",
        rule_id="test-hash-rule",
        rule_version="test-1",
        sha256=None,
        reason="synthetic verdict with no digest",
        reason_code="rule_match",
    )

    result = quarantine_file(store, "det-nohash-1", sample, tmp_path / "quarantine", verdict)

    assert not result.success
    assert "no verified hash" in (result.error or "")
    assert sample.exists()


def test_quarantine_refuses_file_that_changed_since_the_scan(tmp_path: Path) -> None:
    store = _store(tmp_path)
    content = b"original bytes that were scanned"
    sample = tmp_path / "raced.bin"
    sample.write_bytes(content)

    rules = RuleSet(version="test-1", rules=(_hash_rule(content),))
    verdict = scan_path(sample, rules)
    assert verdict.action == "block"

    sample.write_bytes(b"different bytes written after the scan")

    result = quarantine_file(store, "det-raced-1", sample, tmp_path / "quarantine", verdict)

    assert not result.success
    assert "hash mismatch" in (result.error or "")
    assert sample.exists()


def test_restore_refuses_tampered_quarantined_file(tmp_path: Path) -> None:
    store = _store(tmp_path)
    quarantine_root = tmp_path / "quarantine"
    content = b"quarantined bytes subject to tampering"
    sample = tmp_path / "tampered.bin"
    sample.write_bytes(content)

    rules = RuleSet(version="test-1", rules=(_hash_rule(content),))
    verdict = scan_path(sample, rules)
    detection_id = "det-tamper-1"
    _record_detection(store, detection_id, verdict, sample)

    result = quarantine_file(store, detection_id, sample, quarantine_root, verdict)
    assert result.success, result.error
    assert result.item is not None

    Path(result.item.quarantined_path).write_bytes(b"swapped payload")

    restored = restore_quarantine(store, result.item.item_id, quarantine_root)

    assert not restored.success
    assert "tampering" in (restored.error or "")
    assert not sample.exists()
    assert list_quarantine_items(store)[0].restore_result == "refused"


def test_restore_refuses_file_still_matching_a_block_rule(tmp_path: Path) -> None:
    store = _store(tmp_path)
    quarantine_root = tmp_path / "quarantine"
    content = b"still malicious according to the active rule set"
    sample = tmp_path / "still-bad.bin"
    sample.write_bytes(content)

    rules = RuleSet(version="test-1", rules=(_hash_rule(content),))
    verdict = scan_path(sample, rules)
    detection_id = "det-stillbad-1"
    _record_detection(store, detection_id, verdict, sample)

    result = quarantine_file(store, detection_id, sample, quarantine_root, verdict)
    assert result.success, result.error
    assert result.item is not None

    restored = restore_quarantine(store, result.item.item_id, quarantine_root, rules)

    assert not restored.success
    assert "still matches block rule" in (restored.error or "")
    assert not sample.exists()


def test_eicar_detects_and_quarantines_with_the_signed_demo_package(tmp_path: Path) -> None:
    """End-to-end EICAR run against the shipped signed rule package.

    The EICAR string is generated at runtime; nothing malicious is committed.
    Microsoft Defender commonly deletes it before SVS Cyber ever sees it, which
    is a Defender detection and not an SVS Cyber one -- that case is skipped
    explicitly rather than reported as a pass.
    """
    from cyber_os.protection.rule_package import RulePackage

    resources = Path(__file__).parents[1] / "cyber_os" / "protection" / "resources"
    rules = RulePackage.load(
        resources / "demo-manifest.json",
        resources / "demo-manifest.sig",
        (resources / "trusted-rules.pub").read_bytes(),
    )

    sample = tmp_path / "eicar.com"
    try:
        sample.write_bytes(EICAR)
        assert sample.read_bytes() == EICAR
    except OSError as exc:
        pytest.skip(
            "host antivirus (Microsoft Defender) removed the EICAR fixture before "
            f"SVS Cyber could scan it; this is a Defender detection, not an SVS Cyber one: {exc}"
        )

    store = _store(tmp_path)
    verdict = scan_path(sample, rules)
    assert (verdict.status, verdict.action) == ("detected", "block"), verdict.reason
    assert verdict.rule_id == "eicar-test-file"

    detection_id = "det-eicar-1"
    _record_detection(store, detection_id, verdict, sample)
    result = quarantine_file(store, detection_id, sample, tmp_path / "quarantine", verdict)

    assert result.success, result.error
    assert result.item is not None
    assert not sample.exists()
    quarantined = Path(result.item.quarantined_path)
    try:
        assert quarantined.read_bytes() == EICAR
    except OSError as exc:
        pytest.skip(f"Microsoft Defender removed the quarantined EICAR copy: {exc}")
