from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cyber_os.protection.models import DetectionRule, RuleSet
from cyber_os.protection import scanner
from cyber_os.protection.scanner import scan_path


def _rule_set(*rules: DetectionRule) -> RuleSet:
    return RuleSet(version="test-2", rules=tuple(rules))


def _hash_rule(content: bytes, *, action: str = "block") -> DetectionRule:
    return DetectionRule(
        id="hash-1",
        kind="sha256",
        value=hashlib.sha256(content).hexdigest(),
        action=action,  # type: ignore[arg-type]
        confidence="high" if action == "block" else "low",
    )


def test_sha256_block_rule_returns_verified_block_verdict(tmp_path: Path) -> None:
    content = b"STAI inert antivirus test marker"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(content)

    verdict = scan_path(sample, _rule_set(_hash_rule(content)))

    assert (verdict.status, verdict.action, verdict.rule_id) == (
        "detected",
        "block",
        "hash-1",
    )
    assert verdict.sha256 == hashlib.sha256(content).hexdigest()


def test_observe_match_never_blocks(tmp_path: Path) -> None:
    content = b"benign but observable test marker"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(content)

    verdict = scan_path(sample, _rule_set(_hash_rule(content, action="observe")))

    assert verdict.status == "detected"
    assert verdict.action == "allow"


def test_clean_file_returns_allow_verdict(tmp_path: Path) -> None:
    sample = tmp_path / "clean.txt"
    sample.write_text("ordinary user content", encoding="utf-8")

    verdict = scan_path(sample, _rule_set())

    assert verdict.status == "clean"
    assert verdict.action == "allow"


def test_file_mutated_during_scan_returns_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = b"STAI inert antivirus test marker"
    sample = tmp_path / "sample.bin"
    sample.write_bytes(content)
    original_reader = scanner._read_digest

    def mutate_after_read(path: Path, expected: tuple) -> str:
        digest = original_reader(path, expected)
        path.write_bytes(content + b" changed")
        return digest

    monkeypatch.setattr(scanner, "_read_digest", mutate_after_read)

    verdict = scan_path(sample, _rule_set(_hash_rule(content)))

    assert verdict.status == "unknown"
    assert verdict.action == "allow"


def test_yara_timeout_returns_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"YARA scan timeout fixture")
    yara_rule = DetectionRule(
        id="yara-1",
        kind="yara",
        value='rule marker { strings: $a = "timeout" condition: $a }',
        action="block",
        confidence="high",
    )

    def timeout(_path: Path, _rules: tuple[DetectionRule, ...], _timeout: int):
        raise scanner._YaraTimeout("YARA match exceeded its time budget")

    monkeypatch.setattr(scanner, "_match_yara", timeout)

    verdict = scan_path(sample, _rule_set(yara_rule))

    assert verdict.status == "unknown"
    assert verdict.action == "allow"


def test_yara_rule_matches_verified_package(tmp_path: Path) -> None:
    pytest.importorskip("yara")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"STAI_YARA_TEST_MARKER")
    yara_rule = DetectionRule(
        id="yara-1",
        kind="yara",
        value=(
            'rule marker { strings: $a = "STAI_YARA_TEST_MARKER" '
            "condition: $a }"
        ),
        action="block",
        confidence="high",
    )

    verdict = scan_path(sample, _rule_set(yara_rule))

    assert (verdict.status, verdict.action, verdict.rule_id) == (
        "detected",
        "block",
        "yara-1",
    )
