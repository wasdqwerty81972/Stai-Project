"""Importer integration uses the same validated store as protection detection."""

import importlib
import io
import zipfile

from cyber_os.protection.store import ThreatIntelStore


def test_imported_export_is_visible_to_detection_and_invalid_hashes_are_dropped(tmp_path):
    importer = importlib.import_module("import_threat_intel")
    database = tmp_path / "intel.db"
    digest = "a" * 64
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("full_sha256.txt", digest + "\n" + "z" * 64 + "\n" + digest)
    result = importer.import_feed(database, fetcher=lambda *_: payload.getvalue())
    assert result["status"] == "success"
    store = ThreatIntelStore(database)
    try:
        record = store.lookup_hash(digest)
        assert record is not None
        assert record.source == "abusech_malwarebazaar"
        assert record.confidence <= 90
        assert store.stats()["total_rows"] == 1
    finally:
        store.close()


def test_import_failure_preserves_existing_indicators(tmp_path):
    importer = importlib.import_module("import_threat_intel")
    database = tmp_path / "intel.db"
    digest = "b" * 64
    importer.import_feed(database, fetcher=lambda *_: digest.encode())

    def fail(*_):
        raise OSError("feed unavailable")

    result = importer.import_feed(database, fetcher=fail)
    assert result["status"] == "fetch_failed"
    store = ThreatIntelStore(database)
    try:
        assert store.lookup_hash(digest) is not None
    finally:
        store.close()


def test_cli_imports_recent_metadata_locally_under_existing_trust_ceiling(tmp_path, monkeypatch):
    importer = importlib.import_module("import_threat_intel")
    intel = importlib.import_module("cyber_threat_intel")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(intel, "http_fetch", lambda *_: (
        '2025-07-01,"' + "c" * 64 + '","' + "d" * 32 + '","' + "e" * 40 + '"\n'
    ).encode())
    assert importer.main([]) == 0
    store = ThreatIntelStore(tmp_path / "threat-intel.db")
    try:
        record = store.lookup_hash("c" * 64)
        assert record is not None
        assert record.source == "abusech_malwarebazaar_recent"
        # A feed alias has no authority beyond the registry's trust ceiling.
        assert record.verification == "unverified"
    finally:
        store.close()
