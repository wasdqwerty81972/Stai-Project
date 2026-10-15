"""Regression checks for honest scan coverage and bounded signed analysis."""

import hashlib
from pathlib import Path

import pytest

from cyber_os.protection import scanner
from cyber_os.protection.models import DetectionRule, RuleSet


def _yara(rule_id: str, source: str, *, block: bool = False) -> DetectionRule:
    return DetectionRule(rule_id, "yara", source, "block" if block else "observe", "high")


def test_partial_yara_nonmatch_is_unknown(tmp_path: Path) -> None:
    pytest.importorskip("yara")
    sample = tmp_path / "safe.txt"
    sample.write_bytes(b"ordinary fixture")
    rules = RuleSet("partial", (
        _yara("broken", "rule broken {"),
        _yara("valid", "rule valid { condition: false }"),
    ))
    verdict = scanner.scan_path(sample, rules)
    assert (verdict.status, verdict.reason_code) == ("unknown", "analysis_unavailable")


def test_observe_match_cannot_hide_failed_blocking_rule(tmp_path: Path) -> None:
    pytest.importorskip("yara")
    sample = tmp_path / "safe.txt"
    sample.write_bytes(b"ordinary fixture")
    rules = RuleSet("partial-observe", (
        _yara("broken-block", "rule broken {", block=True),
        _yara("valid-observe", "rule observed { condition: true }"),
    ))
    verdict = scanner.scan_path(sample, rules)
    assert (verdict.status, verdict.action, verdict.reason_code) == ("unknown", "allow", "analysis_unavailable")


@pytest.mark.parametrize("hash_match", [False, True])
def test_partial_compilation_preserves_verified_detections(tmp_path: Path, hash_match: bool) -> None:
    pytest.importorskip("yara")
    sample = tmp_path / "safe.txt"
    content = b"inert regression fixture"
    sample.write_bytes(content)
    match = (DetectionRule("exact", "sha256", hashlib.sha256(content).hexdigest(), "block", "high")
             if hash_match else _yara("valid", "rule valid { condition: true }", block=True))
    rules = RuleSet("partial-match", (_yara("broken", "rule broken {"), match))
    verdict = scanner.scan_path(sample, rules)
    assert (verdict.status, verdict.action, verdict.rule_id) == ("detected", "block", match.id)


def test_signed_yara_cannot_include_unsigned_local_source(tmp_path: Path) -> None:
    pytest.importorskip("yara")
    included = tmp_path / "unsigned.yar"
    included.write_text("rule injected { condition: true }", encoding="utf-8")
    sample = tmp_path / "safe.txt"
    sample.write_bytes(b"ordinary fixture")
    source = f'include "{included.as_posix()}"'
    verdict = scanner.scan_path(sample, RuleSet("include", (_yara("include", source, block=True),)))
    assert (verdict.status, verdict.action, verdict.reason_code) == ("unknown", "allow", "analysis_unavailable")


@pytest.mark.parametrize("name,value", [
    ("file_timeout_seconds", float("nan")),
    ("file_timeout_seconds", float("inf")),
    ("file_timeout_seconds", True),
    ("max_file_bytes", float("nan")),
    ("max_file_bytes", float("inf")),
    ("max_file_bytes", True),
    ("yara_timeout_seconds", float("nan")),
    ("yara_timeout_seconds", float("inf")),
    ("yara_timeout_seconds", True),
])
def test_invalid_budgets_are_rejected(tmp_path: Path, name: str, value: object) -> None:
    sample = tmp_path / "safe.txt"
    sample.write_bytes(b"fixture")
    verdict = scanner.scan_path(sample, RuleSet("empty", ()), **{name: value})
    assert (verdict.status, verdict.reason_code) == ("unknown", "invalid_budget")


def test_yara_receives_remaining_budget_and_late_results_are_unknown(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "safe.txt"
    sample.write_bytes(b"fixture")
    clock = [10.0]
    monkeypatch.setattr(scanner.time, "monotonic", lambda: clock[0])
    original_read = scanner._read_digest
    def read(*args, **kwargs):
        digest = original_read(*args, **kwargs)
        clock[0] = 12.5
        return digest
    monkeypatch.setattr(scanner, "_read_digest", read)
    budgets = []
    def match(_path, _rules, timeout):
        budgets.append(timeout)
        clock[0] = 14.1
        return ()
    monkeypatch.setattr(scanner, "_match_yara", match)
    verdict = scanner.scan_path(sample, RuleSet("empty", ()), file_timeout_seconds=4)
    assert budgets == [1.5]
    assert (verdict.status, verdict.reason_code) == ("unknown", "time_budget_exceeded")


def test_compilation_time_is_charged_before_yara_matching(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "safe.txt"
    sample.write_bytes(b"fixture")
    rules = (_yara("valid", "rule valid { condition: false }"),)
    clock = [10.0]
    monkeypatch.setattr(scanner.time, "monotonic", lambda: clock[0])
    class Compiled:
        def match(self, **kwargs):
            pytest.fail("matching must not start after compilation exhausted its budget")
    def compile(_self, **kwargs):
        clock[0] = 12.0
        return Compiled()
    monkeypatch.setattr(scanner._RuleIndex, "compiled_yara", compile)
    with pytest.raises(scanner._YaraTimeout):
        scanner._match_yara(sample, rules, 1)


def test_fallback_compilation_stops_between_sources_at_deadline(tmp_path: Path, monkeypatch) -> None:
    yara = pytest.importorskip("yara")
    sample = tmp_path / "safe.txt"
    sample.write_bytes(b"fixture")
    rules = tuple(_yara(f"broken-{i}", "rule broken {") for i in range(20))
    clock = [10.0]
    monkeypatch.setattr(scanner.time, "monotonic", lambda: clock[0])
    calls = []
    def compile(**kwargs):
        calls.append(kwargs["sources"])
        clock[0] += 0.6
        raise yara.SyntaxError("invalid fixture")
    monkeypatch.setattr(yara, "compile", compile)
    with pytest.raises(scanner._YaraTimeout):
        scanner._match_yara(sample, rules, 1)
    assert len(calls) == 2
    # Budget exhaustion is temporary and must not poison the cached index.
    assert scanner.rule_index(rules)._compile_error is None
