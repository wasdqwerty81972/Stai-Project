"""Evidence and visibility contracts for read-only device activity."""

import hashlib
import json
from types import SimpleNamespace

import psutil
import pytest

from cyber_os.protection.models import DetectionRule, RuleSet
from cyber_os.protection.rule_package import RulePackage, rule_set_fingerprint
from ui.device_activity import DeviceActivityCollector, _RESOURCES, merge_protection_service_rules, shannon_entropy


def test_entropy_known_byte_distributions():
    assert shannon_entropy(b"\x00" * 1000) == 0
    assert shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8)
    assert shannon_entropy(b"ab" * 500) == pytest.approx(1)
    assert shannon_entropy(b"") is None


def test_high_entropy_is_review_evidence_not_confirmed_threat(tmp_path):
    target = tmp_path / "packed.exe"
    target.write_bytes(bytes(range(256)) * 10)
    collector = DeviceActivityCollector()
    result = collector._analyze_executable(target, RuleSet("test", ()))
    assert result["classification"] == "needs_review"
    assert result["entropy"] == pytest.approx(8)
    assert "malicious" in result["reason"]
    assert result["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    without_database = collector._analyze_executable(target, None)
    assert without_database["classification"] == "needs_review"
    assert "database unavailable" in without_database["reason"]


def test_verified_hash_block_and_unknown_scan_have_distinct_assessments(tmp_path):
    target = tmp_path / "app.exe"
    target.write_bytes(b"test threat bytes")
    rules = RuleSet("signed-test", (DetectionRule(
        "hash-test", "sha256", hashlib.sha256(target.read_bytes()).hexdigest(), "block", "high"
    ),))
    collector = DeviceActivityCollector()
    blocked = collector._analyze_executable(target, rules)
    assert blocked["classification"] == "known_threat"
    assert blocked["rule_id"] == "hash-test"
    missing = collector._analyze_executable(tmp_path / "missing.exe", rules)
    assert missing["classification"] == "unavailable"
    no_database = collector._analyze_executable(target, None)
    assert no_database["classification"] == "unavailable"


def test_service_rule_metadata_replaces_user_mode_access_error():
    snapshot = {"database": {"available": False, "version": None, "rule_count": 0,
        "demo": False, "coverage": "No authenticated threat database available"},
        "errors": ["Threat database unavailable: manifest or signature could not be read"],
        "processes": [{"assessment": {"classification": "unavailable", "reason": "old error"}}]}
    status = {"rules_trusted": True, "rules_version": "svs-eicar-demo-1",
        "rule_count": 1, "sha256_rule_count": 1, "yara_rule_count": 0}

    result = merge_protection_service_rules(snapshot, status)

    assert result["database"]["available"] is True
    assert result["database"]["version"] == "svs-eicar-demo-1"
    assert result["database"]["rule_count"] == 1
    assert result["database"]["analysis_available"] is False
    assert "process-level rule matching is unavailable" in result["database"]["coverage"]
    assert not any(error.startswith("Threat database unavailable:") for error in result["errors"])
    assert result["processes"][0]["assessment"]["classification"] == "unavailable"


def test_untrusted_service_rule_metadata_does_not_override_database_error():
    snapshot = {"database": {"available": False, "version": None, "rule_count": 0,
        "demo": False, "coverage": "No authenticated threat database available"}}
    status = {"rules_trusted": False, "rules_version": "untrusted", "rule_count": 10}

    result = merge_protection_service_rules(snapshot, status)

    assert result["database"]["available"] is False
    assert result["database"]["version"] is None


def test_collector_reuses_embedded_rules_only_when_service_fingerprint_matches(tmp_path, monkeypatch):
    protected_rules = tmp_path / "protected" / "rules"
    protected_rules.mkdir(parents=True)
    manifest = protected_rules / "manifest.json"
    signature = protected_rules / "manifest.sig"
    manifest.write_text("protected by the service", encoding="utf-8")
    signature.write_bytes(b"protected")
    monkeypatch.setenv("STAI_PROTECTION_DATA_DIR", str(tmp_path / "protected"))

    original_load = RulePackage.load
    embedded = original_load(
        _RESOURCES / "demo-manifest.json",
        _RESOURCES / "demo-manifest.sig",
        (_RESOURCES / "trusted-rules.pub").read_bytes(),
    )

    def deny_protected_manifest(path, sig_path, public_key):
        if path == manifest:
            raise PermissionError("service-only file")
        return original_load(path, sig_path, public_key)

    monkeypatch.setattr(RulePackage, "load", deny_protected_manifest)
    collector = DeviceActivityCollector()
    collector.set_protection_status({
        "rules_trusted": True,
        "rules_version": embedded.version,
        "rule_count": len(embedded.rules),
        "rules_fingerprint": rule_set_fingerprint(embedded),
    })

    collector._load_database(now=1)

    assert collector._rules == embedded
    assert collector._database["analysis_available"] is True
    assert collector._database["fingerprint"] == rule_set_fingerprint(embedded)


def test_snapshot_keeps_inaccessible_process_and_reports_network_denial(monkeypatch):
    process = SimpleNamespace(pid=44, info={"pid": 44, "name": None, "username": None,
        "exe": None, "status": "running", "memory_info": None, "create_time": 1})
    monkeypatch.setattr(psutil, "process_iter", lambda *args, **kwargs: iter([process]))
    def denied(*args, **kwargs):
        raise psutil.AccessDenied()
    monkeypatch.setattr(psutil, "net_connections", denied)
    monkeypatch.setattr(psutil, "net_io_counters", lambda **kwargs: SimpleNamespace(bytes_sent=100, bytes_recv=200))
    result = DeviceActivityCollector().snapshot()
    assert len(result["processes"]) == 1
    row = result["processes"][0]
    assert row["pid"] == 44
    assert row["name"] == "Process 44"
    assert row["cpu_percent"] is None
    assert row["assessment"]["classification"] == "unavailable"
    assert row["visibility_errors"]
    assert any("Network" in error for error in result["errors"])


def test_unsigned_installed_rules_are_never_used(tmp_path, monkeypatch):
    root = tmp_path / "rules"
    root.mkdir()
    (root / "manifest.json").write_text('{"version":"attacker","rules":[]}')
    (root / "manifest.sig").write_bytes(b"x" * 64)
    monkeypatch.setenv("STAI_PROTECTION_DATA_DIR", str(tmp_path))
    collector = DeviceActivityCollector()
    collector._load_database(1.0)
    assert not collector._database["available"]
    assert any("signature" in error.lower() for error in collector._database_errors)


def test_authenticated_database_match_does_not_certify_unmatched_files(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    target = tmp_path / "test.exe"
    target.write_bytes(b"non-malicious synthetic signature fixture")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"version": "signed-test", "rules": [{"id": "test-hash", "kind": "sha256",
        "value": hashlib.sha256(target.read_bytes()).hexdigest(), "action": "block", "confidence": "high"}]}))
    signer = Ed25519PrivateKey.generate()
    signature = tmp_path / "manifest.sig"
    signature.write_bytes(signer.sign(manifest.read_bytes()))
    rules = RulePackage.load(manifest, signature, signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    collector = DeviceActivityCollector()
    assert collector._analyze_executable(target, rules)["classification"] == "known_threat"
    target.write_bytes(b"ordinary executable placeholder")
    result = collector._analyze_executable(target, rules)
    assert result["classification"] == "no_known_match"
    assert "not proof" in result["reason"]


def test_file_above_scan_budget_is_unavailable(tmp_path):
    target = tmp_path / "oversized.exe"
    with target.open("wb") as stream:
        stream.truncate(65 * 1024 * 1024)
    result = DeviceActivityCollector()._analyze_executable(target, RuleSet("test", ()))
    assert result["classification"] == "unavailable"
    assert result["sampled_bytes"] == 256 * 1024


def test_network_and_cpu_rates_use_elapsed_time_and_preserve_connections(monkeypatch):
    import ui.device_activity as activity
    current = [100.0]
    cpu_total = [8.0]
    traffic = [SimpleNamespace(bytes_recv=1000, bytes_sent=2000)]
    process = SimpleNamespace(pid=44, info={"pid": 44, "name": "test", "username": "user",
        "exe": None, "status": "running", "memory_info": SimpleNamespace(rss=1024), "create_time": 1},
        cpu_times=lambda: SimpleNamespace(user=cpu_total[0], system=0))
    monkeypatch.setattr(activity.time, "monotonic", lambda: current[0])
    monkeypatch.setattr(psutil, "cpu_count", lambda: 4)
    monkeypatch.setattr(psutil, "process_iter", lambda **kwargs: iter([process]))
    monkeypatch.setattr(psutil, "Process", lambda pid: SimpleNamespace(create_time=lambda: 1))
    monkeypatch.setattr(psutil, "net_io_counters", lambda **kwargs: traffic[0])
    monkeypatch.setattr(psutil, "net_connections", lambda **kwargs: [SimpleNamespace(pid=44,
        type=activity.socket.SOCK_STREAM, family=activity.socket.AF_INET6,
        laddr=("::1", 1234), raddr=("::1", 80), status="ESTABLISHED")])
    collector = DeviceActivityCollector()
    first = collector.snapshot()
    assert first["processes"][0]["cpu_percent"] is None
    assert first["network"]["download_bytes_sec"] is None
    current[0] = 104.0
    cpu_total[0] = 10.0
    traffic[0] = SimpleNamespace(bytes_recv=5000, bytes_sent=4000)
    second = collector.snapshot()
    assert second["processes"][0]["cpu_percent"] == pytest.approx(12.5)
    assert second["network"]["download_bytes_sec"] == pytest.approx(1000)
    assert second["network"]["upload_bytes_sec"] == pytest.approx(500)
    assert second["connections"][0]["local_address"] == "[::1]:1234"
    assert second["connections"][0]["process_name"] == "test"


def test_observe_rule_is_review_only(tmp_path):
    target = tmp_path / "app.exe"
    target.write_bytes(b"observe-only fixture")
    rules = RuleSet("test", (DetectionRule("observe", "sha256",
        hashlib.sha256(target.read_bytes()).hexdigest(), "observe", "medium"),))
    result = DeviceActivityCollector()._analyze_executable(target, rules)
    assert result["classification"] == "needs_review"
    assert result["rule_id"] == "observe"


def test_file_change_during_scan_discards_prior_verdict(tmp_path, monkeypatch):
    import ui.device_activity as activity
    target = tmp_path / "app.exe"
    target.write_bytes(b"initial bytes")
    original_scan = activity.scan_path
    def racing_scan(path, rules, **kwargs):
        verdict = original_scan(path, rules, **kwargs)
        path.write_bytes(b"replaced bytes during scan")
        return verdict
    monkeypatch.setattr(activity, "scan_path", racing_scan)
    result = DeviceActivityCollector()._analyze_executable(target, RuleSet("test", ()))
    assert result["classification"] == "unavailable"
    assert "changed" in result["reason"]
    assert result["sha256"] is None


def test_temporary_analysis_failure_retries_without_file_metadata_change(tmp_path, monkeypatch):
    import ui.device_activity as activity
    from cyber_os.protection.models import ScanVerdict
    target = tmp_path / "app.exe"
    target.write_bytes(b"ordinary executable fixture")
    original_scan = activity.scan_path
    attempts = [0]
    def temporarily_unavailable(path, rules, **kwargs):
        attempts[0] += 1
        if attempts[0] == 1:
            return ScanVerdict("unknown", "allow", None, rules.version, None, "temporary read denial", "read_error")
        return original_scan(path, rules, **kwargs)
    monkeypatch.setattr(activity, "scan_path", temporarily_unavailable)
    collector = DeviceActivityCollector()
    collector._rules = RuleSet("test", ())
    assert collector._executable_assessment(str(target))["classification"] == "pending"
    for future in collector._pending.values():
        future.result(timeout=5)
    collector._collect_finished()
    assert collector._executable_assessment(str(target))["classification"] == "unavailable"
    now = activity.time.monotonic()
    monkeypatch.setattr(activity.time, "monotonic", lambda: now + 31)
    assert collector._executable_assessment(str(target))["classification"] == "pending"
    for future in collector._pending.values():
        future.result(timeout=5)
    collector._collect_finished()
    assert collector._executable_assessment(str(target))["classification"] == "no_known_match"
    collector._executor.shutdown(wait=True)
