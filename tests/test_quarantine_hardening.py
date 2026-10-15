"""Regression coverage for safe quarantine restoration."""

import hashlib
from contextlib import contextmanager
from pathlib import Path

import pytest

from cyber_os.protection import quarantine as quarantine_module
from cyber_os.protection.models import DetectionRule, RuleSet, ScanVerdict
from cyber_os.protection.quarantine import quarantine_file, restore_quarantine
from cyber_os.protection.store import DetectionRecord, ProtectionStore


@pytest.fixture
def contained(tmp_path):
    store = ProtectionStore(tmp_path / "protection.db")
    source = tmp_path / "sample.txt"
    source.write_bytes(b"harmless quarantine regression fixture")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    verdict = ScanVerdict("detected", "block", "fixture", "1", digest, "fixture")
    store.record_detection(DetectionRecord(
        "fixture", digest, "fixture", "1", "block", "high", "high", None,
        source.stat().st_size, str(source), "2026-10-15", False,
    ))
    root = tmp_path / "quarantine"
    result = quarantine_file(store, "fixture", source, root, verdict)
    assert result.success, result.error
    try:
        yield store, source, root, result.item
    finally:
        store._get_conn().close()


def test_restore_refuses_unknown_scan(contained, monkeypatch):
    store, source, root, item = contained
    monkeypatch.setattr("cyber_os.protection.scanner.scan_path", lambda *a, **k:
                        ScanVerdict("unknown", "allow", None, "1", None, "unavailable"))
    result = restore_quarantine(store, item.item_id, root, RuleSet("1", ()))
    assert not result.success
    assert not source.exists()
    assert Path(item.quarantined_path).exists()


def test_restore_can_retry_after_block_rule_removed(contained):
    store, source, root, item = contained
    rules = RuleSet("1", (DetectionRule("fixture", "sha256", item.sha256, "block", "high"),))
    assert not restore_quarantine(store, item.item_id, root, rules).success
    result = restore_quarantine(store, item.item_id, root, RuleSet("2", ()))
    assert result.success, result.error
    assert source.exists()


def test_restore_rejects_record_outside_quarantine_root(contained, tmp_path):
    store, source, root, item = contained
    external = tmp_path / "external.txt"
    Path(item.quarantined_path).rename(external)
    with store._transaction() as conn:
        conn.execute("UPDATE quarantine_items SET quarantined_path = ? WHERE item_id = ?",
                     (str(external), item.item_id))
    result = restore_quarantine(store, item.item_id, root)
    assert not result.success
    assert external.exists()
    assert not source.exists()


def test_restore_rejects_quarantined_symlink(contained, tmp_path):
    store, source, root, item = contained
    quarantined = Path(item.quarantined_path)
    external = tmp_path / "external.txt"
    quarantined.rename(external)
    try:
        quarantined.symlink_to(external)
    except OSError:
        pytest.skip("symbolic link creation requires Windows privileges")
    result = restore_quarantine(store, item.item_id, root)
    assert not result.success
    assert external.exists()
    assert not source.exists()


def test_restore_does_not_overwrite_unreadable_existing_file(contained, monkeypatch):
    store, source, root, item = contained
    source.write_bytes(b"replacement must survive")
    original_digest = quarantine_module._digest_file

    def fail_read(path):
        if path == source:
            raise PermissionError("simulated read denial")
        return original_digest(path)

    monkeypatch.setattr(quarantine_module, "_digest_file", fail_read)
    result = restore_quarantine(store, item.item_id, root)
    assert not result.success
    assert source.read_bytes() == b"replacement must survive"
    assert Path(item.quarantined_path).exists()


def test_restore_does_not_overwrite_file_created_during_move(contained, monkeypatch):
    store, source, root, item = contained
    original_exists = Path.exists
    created = False

    def create_on_exists(path):
        nonlocal created
        if path == source and not created:
            created = True
            source.write_bytes(b"concurrent replacement")
            return False
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", create_on_exists)
    result = restore_quarantine(store, item.item_id, root)
    assert not result.success
    assert source.read_bytes() == b"concurrent replacement"
    assert Path(item.quarantined_path).exists()


def test_restore_keeps_execute_denial_when_destination_verification_fails(contained, monkeypatch):
    store, source, root, item = contained
    original_digest = quarantine_module._digest_file
    released = []

    def changed_destination(path):
        return "0" * 64 if path == source else original_digest(path)

    monkeypatch.setattr(quarantine_module, "_digest_file", changed_destination)
    monkeypatch.setattr(quarantine_module, "_allow_execute", released.append)
    result = restore_quarantine(store, item.item_id, root)
    assert not result.success
    assert released == []


@pytest.mark.parametrize("failure", ["database", "post_move_hash"])
def test_quarantine_rollback_preserves_recreated_original(tmp_path, monkeypatch, failure):
    store = ProtectionStore(tmp_path / "protection.db")
    source = tmp_path / "sample.txt"
    content = b"inert quarantine rollback fixture"
    source.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    verdict = ScanVerdict("detected", "block", "fixture", "1", digest, "fixture")
    root = tmp_path / "quarantine"

    if failure == "database":
        @contextmanager
        def fail_transaction():
            source.write_bytes(b"concurrent user replacement")
            raise OSError("simulated persistence failure")
            yield
        monkeypatch.setattr(store, "_transaction", fail_transaction)
    else:
        original_digest = quarantine_module._digest_file
        def fail_verification(path):
            if path != source:
                source.write_bytes(b"concurrent user replacement")
                return "0" * 64
            return original_digest(path)
        monkeypatch.setattr(quarantine_module, "_digest_file", fail_verification)

    try:
        result = quarantine_file(store, "fixture", source, root, verdict)
        assert not result.success
        assert source.read_bytes() == b"concurrent user replacement"
        assert len(list(root.glob("*.stai_quarantine"))) == 1
    finally:
        store._get_conn().close()
