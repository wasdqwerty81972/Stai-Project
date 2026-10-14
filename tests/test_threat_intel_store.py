"""Threat-intelligence store and feed-ingestion tests.

These pin the invariants that keep a feed from becoming a blocklist:

* a domain/IP/URL appearing in a feed is NEVER sufficient to block;
* a single uncorroborated report is NEVER sufficient to block;
* a feed cannot promote its own trust level or confidence;
* synthetic benchmark rows cannot enter a production detection database;
* digest lookups use an index, not a table scan;
* a feed generation swaps in atomically and can be rolled back;
* the whole ingestion path runs offline against a fixture.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import cyber_threat_intel as intel
from cyber_os.protection.store import (
    BLOCK_ELIGIBLE_VERIFICATION,
    DEFAULT_MIN_BLOCK_CONFIDENCE,
    IndicatorRecord,
    IntelIntegrityError,
    ProtectionStore,
    SyntheticDataRejected,
    ThreatIntelStore,
    normalise_hash,
    trust_for_source,
)


SHA256_A = "a" * 64
SHA256_B = "b" * 64
SHA1_A = "c" * 40
MD5_A = "d" * 32


@pytest.fixture()
def store(tmp_path: Path) -> ThreatIntelStore:
    return ThreatIntelStore(tmp_path / "intel.db")


@pytest.fixture()
def bench_store(tmp_path: Path) -> ThreatIntelStore:
    return ThreatIntelStore(tmp_path / "bench.db", allow_synthetic=True)


def _record(**overrides) -> IndicatorRecord:
    base = dict(
        indicator_type="sha256",
        indicator_value=SHA256_A,
        source="abusech_malwarebazaar",
        confidence=90,
        severity="high",
        verification="confirmed",
        feed_version="test-1",
        first_seen="2026-10-01T00:00:00",
        last_seen="2026-10-14T00:00:00",
    )
    base.update(overrides)
    return IndicatorRecord(**base)  # type: ignore[arg-type]


# --- schema completeness --------------------------------------------------


def test_schema_carries_every_required_intel_field(store: ThreatIntelStore) -> None:
    columns = {
        row[1]
        for row in store._get_conn().execute("PRAGMA table_info(intel_indicators)")
    }
    required = {
        "sha256", "sha1", "md5", "threat_family", "indicator_type", "confidence",
        "severity", "source", "source_timestamp", "first_seen", "last_seen",
        "verification", "freshness_ttl_hours", "feed_version",
    }
    assert required <= columns, f"missing: {sorted(required - columns)}"


def test_freshness_is_derived_not_assumed() -> None:
    fresh = _record(last_seen="2026-10-14T00:00:00", freshness_ttl_hours=240)
    stale = _record(last_seen="2020-01-01T00:00:00", freshness_ttl_hours=240)
    from datetime import datetime

    now = datetime(2026, 10, 14, 1, 0, 0)
    assert fresh.freshness(now=now) == "fresh"
    assert stale.freshness(now=now) == "expired"


def test_unparseable_last_seen_is_expired_not_fresh() -> None:
    assert _record(last_seen="not-a-date").freshness() == "expired"


# --- the confidence model -------------------------------------------------


def test_domain_in_a_feed_never_blocks(store: ThreatIntelStore) -> None:
    store.upsert_indicators([
        _record(indicator_type="domain", indicator_value="evil.example",
                source="abusech_threatfox", confidence=100, verification="confirmed"),
    ])
    decision = store.block_decision("domain", "evil.example")
    assert decision.block is False
    assert decision.verdict == "suspicious"
    assert "never auto-blocked" in decision.reason


def test_ip_in_a_feed_never_blocks(store: ThreatIntelStore) -> None:
    store.upsert_indicators([
        _record(indicator_type="ip", indicator_value="203.0.113.7",
                source="abusech_feodotracker", confidence=100, verification="confirmed"),
    ])
    assert store.block_decision("ip", "203.0.113.7").block is False


def test_single_reported_hash_does_not_block(store: ThreatIntelStore) -> None:
    store.upsert_indicators([
        _record(source="abusech_threatfox", verification="reported", confidence=50),
    ])
    decision = store.block_decision("sha256", SHA256_A)
    assert decision.block is False
    assert decision.verdict == "suspicious"
    assert "below the" in decision.reason


def test_confirmed_authoritative_hash_blocks(store: ThreatIntelStore) -> None:
    store.upsert_indicators([_record()])
    decision = store.block_decision("sha256", SHA256_A)
    assert decision.block is True
    assert decision.verdict == "block"
    assert decision.record is not None
    assert decision.record.verification == "confirmed"


def test_retracted_record_does_not_block(store: ThreatIntelStore) -> None:
    store.upsert_indicators([_record(verification="retracted")])
    decision = store.block_decision("sha256", SHA256_A)
    assert decision.block is False
    assert "retracted" in decision.reason


def test_expired_record_does_not_block(store: ThreatIntelStore) -> None:
    store.upsert_indicators([
        _record(last_seen="2000-01-01T00:00:00", freshness_ttl_hours=24),
    ])
    decision = store.block_decision("sha256", SHA256_A)
    assert decision.block is False
    assert "expired" in decision.reason


def test_miss_is_unknown_never_clean(store: ThreatIntelStore) -> None:
    decision = store.block_decision("sha256", SHA256_B)
    assert decision.block is False
    # The absence of intel must not be readable as a clean bill of health.
    assert decision.verdict == "unknown"


# --- trust cannot be self-granted ----------------------------------------


def test_unregistered_source_cannot_claim_confirmed(store: ThreatIntelStore) -> None:
    store.upsert_indicators([
        _record(source="totally_legit_feed", verification="confirmed", confidence=100),
    ])
    record = store.lookup_hash(SHA256_A)
    assert record is not None
    assert record.verification == "unverified"
    assert record.confidence == 0
    assert store.block_decision("sha256", SHA256_A).block is False


def test_aggregator_cannot_claim_confirmed_on_a_hash(store: ThreatIntelStore) -> None:
    # ThreatFox aggregates reports; it does not analyse samples itself.
    store.upsert_indicators([
        _record(source="abusech_threatfox", verification="confirmed", confidence=100),
    ])
    record = store.lookup_hash(SHA256_A)
    assert record is not None
    assert record.verification == "reported"
    assert record.confidence <= trust_for_source("abusech_threatfox").default_confidence


def test_two_independent_sources_escalate_to_corroborated(store: ThreatIntelStore) -> None:
    store.upsert_indicators([_record(source="abusech_threatfox", verification="reported",
                                     confidence=50)])
    assert store.lookup_hash(SHA256_A).verification == "reported"  # type: ignore[union-attr]

    store.upsert_indicators([_record(source="otx", verification="reported", confidence=40)])
    record = store.lookup_hash(SHA256_A)
    assert record is not None
    assert record.verification == "corroborated"
    assert record.corroborations >= 2


def test_corroboration_alone_still_needs_confidence(store: ThreatIntelStore) -> None:
    # Two low-trust sources agreeing clears the verification bar but not the
    # confidence bar, so this must still not block.
    store.upsert_indicators([_record(source="abusech_threatfox", verification="reported",
                                     confidence=50)])
    store.upsert_indicators([_record(source="otx", verification="reported", confidence=40)])
    decision = store.block_decision("sha256", SHA256_A)
    assert decision.record is not None
    assert decision.record.verification in BLOCK_ELIGIBLE_VERIFICATION
    assert decision.record.confidence < DEFAULT_MIN_BLOCK_CONFIDENCE
    assert decision.block is False


# --- synthetic data containment ------------------------------------------


def test_production_store_rejects_synthetic_rows(store: ThreatIntelStore) -> None:
    counters = store.upsert_indicators([_record(synthetic=True)])
    assert counters["rejected"] == 1
    assert counters["inserted"] == 0
    assert store.lookup_hash(SHA256_A) is None


def test_production_bulk_load_rejects_synthetic(store: ThreatIntelStore) -> None:
    with pytest.raises(SyntheticDataRejected):
        store.bulk_load_hashes(
            [SHA256_A], source="synthetic_benchmark", feed_version="x", synthetic=True
        )


def test_synthetic_row_can_never_block_even_in_a_benchmark_store(
    bench_store: ThreatIntelStore,
) -> None:
    bench_store.bulk_load_hashes(
        [SHA256_A], source="synthetic_benchmark", feed_version="bench-1", synthetic=True
    )
    assert bench_store.count_unique_hashes() == 0
    assert bench_store.count_unique_hashes(include_synthetic=True) == 1
    decision = bench_store.block_decision("sha256", SHA256_A)
    assert decision.block is False
    assert "synthetic" in decision.reason


def test_integrity_check_flags_synthetic_leak(tmp_path: Path) -> None:
    bench = ThreatIntelStore(tmp_path / "leak.db", allow_synthetic=True)
    bench.bulk_load_hashes(
        [SHA256_A], source="synthetic_benchmark", feed_version="bench-1", synthetic=True
    )
    bench.close()
    production = ThreatIntelStore(tmp_path / "leak.db")
    report = production.verify_integrity()
    assert report["ok"] is False
    assert any("synthetic" in problem for problem in report["problems"])


# --- indexes, not table scans --------------------------------------------


@pytest.mark.parametrize("column", ["sha256", "sha1", "md5"])
def test_digest_lookup_uses_an_index(store: ThreatIntelStore, column: str) -> None:
    plan = " ".join(
        row[-1]
        for row in store._get_conn().execute(
            f"EXPLAIN QUERY PLAN SELECT * FROM intel_indicators WHERE {column} = ?",
            ("0" * 64,),
        )
    )
    assert "SEARCH" in plan, plan
    assert "SCAN intel_indicators" not in plan, plan


def test_network_indicator_lookup_uses_an_index(store: ThreatIntelStore) -> None:
    plan = " ".join(
        row[-1]
        for row in store._get_conn().execute(
            "EXPLAIN QUERY PLAN SELECT * FROM intel_indicators "
            "WHERE indicator_type = ? AND indicator_value = ?",
            ("domain", "evil.example"),
        )
    )
    assert "SEARCH" in plan, plan


def test_cross_hash_lookup_finds_the_same_record(store: ThreatIntelStore) -> None:
    store.upsert_indicators([_record(sha1=SHA1_A, md5=MD5_A)])
    for digest in (SHA256_A, SHA1_A, MD5_A):
        assert store.lookup_hash(digest) is not None, digest


def test_normalise_hash_rejects_non_digests() -> None:
    assert normalise_hash("deadbeef") is None
    assert normalise_hash("z" * 64) is None
    assert normalise_hash(SHA256_A.upper()) == ("sha256", SHA256_A)


# --- atomic update, rollback, corruption recovery ------------------------


def test_promote_is_atomic_and_keeps_a_rollback_generation(tmp_path: Path) -> None:
    live = ThreatIntelStore(tmp_path / "intel.db")
    live.upsert_indicators([_record(indicator_value=SHA256_A)])
    assert live.count_unique_hashes() == 1

    staging = live.open_staging()
    staging.upsert_indicators([
        _record(indicator_value=SHA256_B, sha256=SHA256_B),
        _record(indicator_value=SHA1_A, indicator_type="sha1"),
    ])
    staging.close()

    result = live.promote_staging(min_rows=2)
    assert result["promoted"] is True
    assert live.lookup_hash(SHA256_B) is not None
    # The old generation is gone from the live file but preserved on disk.
    assert live.lookup_hash(SHA256_A) is None
    assert live.previous_path().exists()

    live.rollback()
    assert live.lookup_hash(SHA256_A) is not None
    assert live.lookup_hash(SHA256_B) is None


def test_promote_refuses_a_short_generation(tmp_path: Path) -> None:
    live = ThreatIntelStore(tmp_path / "intel.db")
    live.upsert_indicators([_record()])
    staging = live.open_staging()
    staging.close()

    # A feed outage that downloaded nothing must not wipe the live database.
    with pytest.raises(IntelIntegrityError, match="below the"):
        live.promote_staging(min_rows=1000)
    assert live.lookup_hash(SHA256_A) is not None


def test_rollback_without_a_previous_generation_is_refused(store: ThreatIntelStore) -> None:
    with pytest.raises(IntelIntegrityError, match="no previous generation"):
        store.rollback()


def test_verify_integrity_passes_on_a_healthy_store(store: ThreatIntelStore) -> None:
    report = store.verify_integrity()
    assert report["ok"] is True
    assert report["problems"] == []


def test_corruption_recovers_by_rolling_back(tmp_path: Path) -> None:
    live = ThreatIntelStore(tmp_path / "intel.db")
    live.upsert_indicators([_record()])
    staging = live.open_staging()
    staging.upsert_indicators([_record(indicator_value=SHA256_B, sha256=SHA256_B)])
    staging.close()
    live.promote_staging()
    live.close()

    # Overwrite the header so SQLite cannot read the file at all.
    (tmp_path / "intel.db").write_bytes(b"this is not a database" * 64)
    recovered = ThreatIntelStore(tmp_path / "intel.db")
    outcome = recovered.recover_if_corrupt()
    assert outcome["action"] == "rolled_back"
    assert outcome["integrity"]["ok"] is True
    assert recovered.lookup_hash(SHA256_A) is not None


def test_corruption_without_a_previous_generation_rebuilds_empty_and_warns(
    tmp_path: Path,
) -> None:
    live = ThreatIntelStore(tmp_path / "intel.db")
    live.upsert_indicators([_record()])
    live.close()
    (tmp_path / "intel.db").write_bytes(b"corrupt" * 1024)
    for sidecar in ("intel.db-wal", "intel.db-shm"):
        candidate = tmp_path / sidecar
        if candidate.exists():
            candidate.unlink()

    recovered = ThreatIntelStore(tmp_path / "intel.db")
    outcome = recovered.recover_if_corrupt()
    assert outcome["action"] == "rebuilt_empty"
    assert outcome["integrity"]["ok"] is True
    # An empty rebuild must announce itself, not pose as "no threats known".
    assert "feed pull is required" in outcome["warning"]
    assert recovered.count_unique_hashes() == 0


# --- feed run bookkeeping -------------------------------------------------


def test_feed_runs_record_versions_and_outcomes(store: ThreatIntelStore) -> None:
    run_id = store.start_feed_run("abusech_threatfox", "tf-1")
    store.finish_feed_run(run_id, status="completed", inserted=3, updated=1)
    last = store.last_feed_run("abusech_threatfox")
    assert last is not None
    assert last["status"] == "completed"
    assert last["feed_version"] == "tf-1"
    assert last["inserted"] == 3


def test_failed_feed_run_records_the_error(store: ThreatIntelStore) -> None:
    run_id = store.start_feed_run("abusech_urlhaus", "uh-1")
    store.finish_feed_run(run_id, status="failed", error="connection reset")
    last = store.last_feed_run("abusech_urlhaus")
    assert last is not None
    assert last["status"] == "failed"
    assert "connection reset" in last["error"]


# --- offline feed ingestion ----------------------------------------------


FEODO_FIXTURE = (
    '[{"ip_address": "203.0.113.5", "port": 8080, "malware": "Emotet", '
    '"first_seen": "2026-10-01 00:00:00"},'
    '{"ip_address": "not-an-ip", "malware": "Junk"}]'
)

THREATFOX_FIXTURE = (
    '{"1": [{"ioc_value": "evil.example", "ioc_type": "domain", '
    '"malware_printable": "AgentTesla", "confidence_level": 75, '
    '"first_seen_utc": "2026-10-02 10:00:00"}],'
    ' "2": [{"ioc_value": "' + SHA256_A + '", "ioc_type": "sha256_hash", '
    '"malware_printable": "Lumma", "confidence_level": 100}],'
    ' "3": [{"ioc_value": "198.51.100.9:443", "ioc_type": "ip:port", '
    '"malware_printable": "Cobalt Strike", "confidence_level": 50}]}'
)

URLHAUS_FIXTURE = "# comment\nhttp://198.51.100.20/payload.bin\n\nhttp://evil.example/a.exe\n"

MALWAREBAZAAR_CSV_FIXTURE = (
    "# comment header\n"
    '"2026-10-01 00:00:00","' + SHA256_A + '","' + MD5_A + '","' + SHA1_A + '",'
    '"reporter","a.exe","exe","application/x-dosexec","Emotet","","50","imphash"\n'
    '"2026-10-02 00:00:00","short","x","y","r","b.exe","exe","m","Family","","0","i"\n'
)

MALWAREBAZAAR_TXT_FIXTURE = (
    "# MalwareBazaar SHA256 export\n" + SHA256_A + "\n" + SHA256_B + "\nnot-a-hash\n"
)


def test_parse_feodo_drops_invalid_ips() -> None:
    records = intel.parse_feodo_json(FEODO_FIXTURE)
    assert [r.indicator_value for r in records] == ["203.0.113.5"]
    assert records[0].threat_family == "Emotet"
    assert records[0].claimed_verification == "reported"


def test_parse_threatfox_splits_types() -> None:
    records = intel.parse_threatfox_json(THREATFOX_FIXTURE)
    by_type = {r.indicator_type: r for r in records}
    assert set(by_type) == {"domain", "sha256", "ip"}
    assert by_type["ip"].indicator_value == "198.51.100.9"  # port stripped
    assert by_type["sha256"].threat_family == "Lumma"


def test_parse_urlhaus_skips_comments_and_blanks() -> None:
    records = intel.parse_urlhaus_text(URLHAUS_FIXTURE)
    assert len(records) == 2
    assert all(r.indicator_type == "url" for r in records)


def test_parse_malwarebazaar_csv_carries_all_three_digests() -> None:
    records = intel.parse_malwarebazaar_csv(MALWAREBAZAAR_CSV_FIXTURE)
    assert len(records) == 1, "the malformed row must be dropped"
    record = records[0]
    assert (record.sha256, record.sha1, record.md5) == (SHA256_A, SHA1_A, MD5_A)
    assert record.threat_family == "Emotet"
    assert record.claimed_verification == "confirmed"


def test_parse_malwarebazaar_txt_drops_non_digests() -> None:
    records = intel.parse_malwarebazaar_sha256_txt(MALWAREBAZAAR_TXT_FIXTURE)
    assert [r.indicator_value for r in records] == [SHA256_A, SHA256_B]


def test_iter_malwarebazaar_sha256_streams_digests() -> None:
    digests = list(intel.iter_malwarebazaar_sha256(MALWAREBAZAAR_TXT_FIXTURE.splitlines()))
    assert digests == [SHA256_A, SHA256_B]


def test_ingest_feed_runs_fully_offline(store: ThreatIntelStore) -> None:
    calls: list[str] = []

    def fixture_fetcher(url: str, headers: dict) -> bytes:
        calls.append(url)
        return THREATFOX_FIXTURE.encode()

    result = intel.ingest_feed("abusech_threatfox", store, fetcher=fixture_fetcher)
    assert result["status"] == "success"
    assert result["parsed"] == 3
    assert result["inserted"] == 3
    assert len(calls) == 1
    assert "CC0" in result["licence"]

    # The hash came in via an aggregator, so it must not be block-eligible.
    assert store.block_decision("sha256", SHA256_A).block is False
    assert store.last_feed_run("abusech_threatfox")["status"] == "completed"  # type: ignore[index]


def test_ingest_feed_reports_a_fetch_failure_without_inserting(
    store: ThreatIntelStore,
) -> None:
    def broken_fetcher(url: str, headers: dict) -> bytes:
        raise OSError("no route to host")

    result = intel.ingest_feed("abusech_urlhaus", store, fetcher=broken_fetcher)
    assert result["status"] == "fetch_failed"
    assert result["ingested"] == 0
    assert store.last_feed_run("abusech_urlhaus")["status"] == "failed"  # type: ignore[index]


def test_ingest_feed_reports_a_missing_credential_without_fetching(
    store: ThreatIntelStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)

    def must_not_be_called(url: str, headers: dict) -> bytes:  # pragma: no cover
        raise AssertionError("fetched despite a missing credential")

    result = intel.ingest_feed(
        "abusech_malwarebazaar_api", store, fetcher=must_not_be_called
    )
    assert result["status"] == "credential_missing"
    assert "ABUSECH_AUTH_KEY" in result["message"]


def test_unknown_feed_is_reported_not_guessed(store: ThreatIntelStore) -> None:
    assert intel.ingest_feed("no_such_feed", store)["status"] == "unknown_feed"


# --- the never-download-a-sample constraint ------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://bazaar.abuse.ch/download/abc123/",
        "https://example.test/get_file?sha256=abc",
        "https://example.test/sample/abc.zip",
        "https://example.test/payload.zip",
    ],
)
def test_sample_download_urls_are_refused_before_any_request(url: str) -> None:
    with pytest.raises(intel.SampleDownloadRefused):
        intel._assert_metadata_only(url)


def test_every_configured_feed_is_metadata_only() -> None:
    for catalogue in (intel.FREE_METADATA_FEEDS, intel.CREDENTIALED_METADATA_FEEDS):
        for name, definition in catalogue.items():
            intel._assert_metadata_only(definition["url"])
            assert "CC0" in definition["licence"] or "abuse.ch" in definition["licence"], name


def test_ingest_feed_refuses_a_sample_download_definition(store: ThreatIntelStore) -> None:
    with pytest.raises(intel.SampleDownloadRefused):
        intel.ingest_feed(
            "rogue",
            store,
            feed_definition={
                "url": "https://example.test/download/sample.zip",
                "format": "urlhaus_text",
                "licence": "none",
            },
        )


def test_zip_member_expansion_ceiling_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("full_sha256.txt", SHA256_A + "\n")
    monkeypatch.setattr(intel, "_MAX_FEED_MEMBER_BYTES", 1)
    with pytest.raises(ValueError, match="above the"):
        intel.unzip_feed_member(buffer.getvalue(), "full_sha256.txt")


def test_zip_member_is_extracted_for_a_zipped_feed() -> None:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("full_sha256.txt", MALWAREBAZAAR_TXT_FIXTURE)
    extracted = intel.unzip_feed_member(buffer.getvalue(), "full_sha256.txt")
    assert intel.parse_malwarebazaar_sha256_txt(extracted)[0].indicator_value == SHA256_A


def test_zipped_bulk_feed_ingests_offline(store: ThreatIntelStore) -> None:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("full_sha256.txt", MALWAREBAZAAR_TXT_FIXTURE)
    payload = buffer.getvalue()

    result = intel.ingest_feed(
        "abusech_malwarebazaar", store, fetcher=lambda url, headers: payload
    )
    assert result["status"] == "success"
    assert result["inserted"] == 2
    # MalwareBazaar analyses its own samples, so these ARE block-eligible.
    assert store.block_decision("sha256", SHA256_A).block is True


# --- bulk loader ----------------------------------------------------------


def test_bulk_load_applies_the_trust_ceiling(store: ThreatIntelStore) -> None:
    counters = store.bulk_load_hashes(
        [SHA256_A, SHA256_B, "garbage"],
        source="abusech_threatfox",
        feed_version="bulk-1",
        verification="confirmed",
    )
    assert counters["inserted"] == 2
    assert counters["rejected"] == 1
    # An aggregator asked for "confirmed" and was capped at "reported".
    assert counters["verification"] == "reported"
    assert store.block_decision("sha256", SHA256_A).block is False


def test_bulk_load_is_idempotent(store: ThreatIntelStore) -> None:
    for _ in range(2):
        store.bulk_load_hashes(
            [SHA256_A], source="abusech_malwarebazaar", feed_version="bulk-1"
        )
    assert store.count_unique_hashes() == 1


def test_stats_separate_present_from_block_eligible(store: ThreatIntelStore) -> None:
    store.bulk_load_hashes(
        [SHA256_A], source="abusech_malwarebazaar", feed_version="v1"
    )
    store.bulk_load_hashes(
        [SHA256_B], source="abusech_threatfox", feed_version="v1", verification="confirmed"
    )
    stats = store.stats()
    assert stats["unique_hashes"] == 2
    # Only the authoritative one can actually block.
    assert stats["block_eligible_hashes"] == 1
    assert stats["synthetic_rows"] == 0


# --- the additive protection.db migration --------------------------------


def test_v6_database_migrates_additively_without_losing_rows(tmp_path: Path) -> None:
    from cyber_os.protection.store import DetectionRecord

    path = tmp_path / "protection.db"
    first = ProtectionStore(path)
    first.record_detection(
        DetectionRecord(
            detection_id="det-1", sha256=SHA256_A, rule_id="r1", rule_version="v1",
            action="block", confidence="high", severity="critical", file_type=".exe",
            size_bytes=10, file_path="C:\\x.exe", created_at="2026-10-01T00:00:00",
            triage_enqueued=False,
        )
    )
    # Rewind to v6 and drop the v7 columns to simulate an older install.
    conn = sqlite3.connect(path)
    for column in ("sha1", "md5", "threat_family", "intel_source", "intel_confidence",
                   "feed_version"):
        conn.execute(f"ALTER TABLE detections DROP COLUMN {column}")
    conn.execute("DELETE FROM schema_version")
    conn.execute("INSERT INTO schema_version (version) VALUES (6)")
    conn.commit()
    conn.close()

    reopened = ProtectionStore(path)
    threats = reopened.list_threats()
    assert [t.detection_id for t in threats] == ["det-1"], "migration lost a row"
    columns = {
        row[1] for row in reopened._get_conn().execute("PRAGMA table_info(detections)")
    }
    assert {"sha1", "md5", "threat_family", "intel_source", "feed_version"} <= columns


def test_detection_sha256_lookup_now_uses_an_index(tmp_path: Path) -> None:
    store = ProtectionStore(tmp_path / "protection.db")
    plan = " ".join(
        row[-1]
        for row in store._get_conn().execute(
            "EXPLAIN QUERY PLAN SELECT detection_id FROM detections WHERE sha256 = ?",
            (SHA256_A,),
        )
    )
    assert "SEARCH" in plan, plan
    assert "SCAN detections" not in plan, plan
