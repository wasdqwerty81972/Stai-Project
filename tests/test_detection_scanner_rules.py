"""Scanner matching layers, rule compilation, and rule-package validation.

Nothing here is mocked except where a test explicitly simulates an unavailable
YARA runtime; the SHA-256 and rule-package paths run for real.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cyber_os.protection import scanner
from cyber_os.protection.models import DetectionRule, RuleSet
from cyber_os.protection.rule_package import InvalidRulePackage, RulePackage, _parse_manifest
from cyber_os.protection.scanner import rule_index, scan_path

RESOURCES = Path(__file__).parents[1] / "cyber_os" / "protection" / "resources"


def _hash_rule(content: bytes, *, rule_id: str = "h1", action: str = "block", confidence: str = "high") -> DetectionRule:
    return DetectionRule(
        id=rule_id,
        kind="sha256",
        value=hashlib.sha256(content).hexdigest(),
        action=action,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
    )


def _filler(count: int) -> list[DetectionRule]:
    return [
        DetectionRule(
            id=f"filler-{i}",
            kind="sha256",
            value=hashlib.sha256(f"filler-{i}".encode()).hexdigest(),
            action="observe",
            confidence="low",
        )
        for i in range(count)
    ]


def test_hash_match_is_found_among_many_rules(tmp_path: Path) -> None:
    content = b"needle in a large signed rule package"
    sample = tmp_path / "needle.bin"
    sample.write_bytes(content)
    rules = RuleSet(
        version="bulk-1",
        rules=tuple(_filler(20_000) + [_hash_rule(content, rule_id="needle")]),
    )

    verdict = scan_path(sample, rules)

    assert (verdict.status, verdict.action, verdict.rule_id) == ("detected", "block", "needle")
    assert verdict.sha256 == hashlib.sha256(content).hexdigest()


def test_rule_index_is_reused_per_rule_set_and_rebuilt_when_rules_change() -> None:
    content = b"index identity fixture"
    first = RuleSet(version="v1", rules=(_hash_rule(content),))
    second = RuleSet(version="v2", rules=(_hash_rule(content, rule_id="h2"),))

    index_a = rule_index(first.rules)
    index_b = rule_index(first.rules)
    assert index_a is index_b, "index must be cached for a stable rule set"

    index_c = rule_index(second.rules)
    assert index_c is not index_a, "a different rule set must rebuild the index"
    assert rule_index(first.rules) is not index_c


def test_duplicate_digest_rules_prefer_the_high_confidence_block(tmp_path: Path) -> None:
    content = b"two rules share one digest"
    sample = tmp_path / "dup.bin"
    sample.write_bytes(content)
    observe = _hash_rule(content, rule_id="observe-first", action="observe", confidence="low")
    block = _hash_rule(content, rule_id="block-second")

    verdict = scan_path(sample, RuleSet(version="dup-1", rules=(observe, block)))

    assert (verdict.status, verdict.action, verdict.rule_id) == (
        "detected",
        "block",
        "block-second",
    )


def test_verdict_follows_current_bytes_when_a_path_is_rescanned(tmp_path: Path) -> None:
    """Matching must be content-addressed, so rewriting a path changes the verdict."""
    malicious = b"malicious content for the signed rule"
    benign = b"benign replacement content"
    sample = tmp_path / "mutating.bin"
    rules = RuleSet(version="content-1", rules=(_hash_rule(malicious),))

    sample.write_bytes(malicious)
    first = scan_path(sample, rules)
    assert (first.status, first.action) == ("detected", "block")

    sample.write_bytes(benign)
    second = scan_path(sample, rules)
    assert (second.status, second.action) == ("clean", "allow")
    assert second.sha256 == hashlib.sha256(benign).hexdigest()

    sample.write_bytes(malicious)
    third = scan_path(sample, rules)
    assert (third.status, third.action) == ("detected", "block")
    assert third.sha256 == first.sha256


def test_missing_yara_runtime_does_not_suppress_a_hash_block(tmp_path: Path) -> None:
    content = b"hash rule must survive a dead yara runtime"
    sample = tmp_path / "s.bin"
    sample.write_bytes(content)
    yara_rule = DetectionRule(
        id="y1",
        kind="yara",
        value='rule m { strings: $a = "nope" condition: $a }',
        action="block",
        confidence="high",
    )

    def unavailable(_path, _rules, _timeout):
        raise scanner._YaraFailure("YARA runtime is unavailable")

    monkey = pytest.MonkeyPatch()
    monkey.setattr(scanner, "_match_yara", unavailable)
    try:
        verdict = scan_path(sample, RuleSet(version="y-1", rules=(_hash_rule(content), yara_rule)))
    finally:
        monkey.undo()

    assert (verdict.status, verdict.action, verdict.rule_id) == ("detected", "block", "h1")


def test_one_invalid_yara_rule_does_not_disable_the_valid_rules(tmp_path: Path) -> None:
    """A broken source must not take the whole YARA layer down with it."""
    pytest.importorskip("yara")
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"STAI_PARTIAL_COMPILE_MARKER")
    broken = DetectionRule(
        id="broken",
        kind="yara",
        value="rule this is not valid yara at all {",
        action="observe",
        confidence="low",
    )
    good = DetectionRule(
        id="good",
        kind="yara",
        value='rule m { strings: $a = "STAI_PARTIAL_COMPILE_MARKER" condition: $a }',
        action="block",
        confidence="high",
    )

    rules = RuleSet(version="partial-1", rules=(broken, good))
    verdict = scan_path(sample, rules)

    assert (verdict.status, verdict.action, verdict.rule_id) == ("detected", "block", "good")
    index = rule_index(rules.rules)
    assert index.compiled_ids == ("good",)
    assert index.failed_ids == ("broken",)


def test_all_invalid_yara_rules_fail_open_to_unknown(tmp_path: Path) -> None:
    pytest.importorskip("yara")
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"content")
    broken = DetectionRule(
        id="broken",
        kind="yara",
        value="rule totally broken {",
        action="observe",
        confidence="low",
    )

    verdict = scan_path(sample, RuleSet(version="broken-1", rules=(broken,)))

    assert (verdict.status, verdict.action) == ("unknown", "allow")
    assert verdict.reason_code == "analysis_unavailable"


def test_shipped_demo_package_is_signed_and_its_rules_all_validate() -> None:
    rules = RulePackage.load(
        RESOURCES / "demo-manifest.json",
        RESOURCES / "demo-manifest.sig",
        (RESOURCES / "trusted-rules.pub").read_bytes(),
    )

    assert len(rules.rules) == 1
    assert [rule.kind for rule in rules.rules] == ["sha256"]
    # Every shipped block rule is high confidence, which is what gates quarantine.
    assert all(rule.confidence == "high" for rule in rules.rules if rule.action == "block")


def test_package_validator_rejects_a_low_confidence_block_rule() -> None:
    """The invariant that makes quarantine safe is enforced at load time."""
    manifest = (
        b'{"version":"bad-1","rules":[{"id":"r1","kind":"sha256","value":"'
        + hashlib.sha256(b"x").hexdigest().encode()
        + b'","action":"block","confidence":"low"}]}'
    )

    with pytest.raises(InvalidRulePackage, match="block rules require high confidence"):
        _parse_manifest(manifest)


def test_package_load_rejects_a_tampered_manifest(tmp_path: Path) -> None:
    tampered = tmp_path / "manifest.json"
    tampered.write_bytes(
        (RESOURCES / "demo-manifest.json").read_bytes().replace(b"svs-eicar-demo-1", b"svs-eicar-demo-2")
    )

    with pytest.raises(InvalidRulePackage, match="signature verification failed"):
        RulePackage.load(
            tampered,
            RESOURCES / "demo-manifest.sig",
            (RESOURCES / "trusted-rules.pub").read_bytes(),
        )
