from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cyber_os.protection.rule_package import RulePackage
from cyber_os.protection.scanner import scan_path


def test_signed_eicar_demo_rule_is_valid_and_names_the_expected_test_file():
    resources = Path(__file__).parents[1] / "cyber_os" / "protection" / "resources"
    rules = RulePackage.load(
        resources / "demo-manifest.json",
        resources / "demo-manifest.sig",
        (resources / "trusted-rules.pub").read_bytes(),
    )
    rule = rules.rules[0]
    eicar_test_digest = hashlib.sha256(
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    ).hexdigest()

    assert rules.version == "svs-eicar-demo-1"
    assert rule.id == "eicar-test-file"
    assert rule.value == eicar_test_digest
    assert rule.action == "block"
    assert rule.confidence == "high"


def test_custom_scanner_detects_canonical_eicar_using_signed_demo_rule(tmp_path: Path) -> None:
    resources = Path(__file__).parents[1] / "cyber_os" / "protection" / "resources"
    rules = RulePackage.load(
        resources / "demo-manifest.json",
        resources / "demo-manifest.sig",
        (resources / "trusted-rules.pub").read_bytes(),
    )
    sample = tmp_path / "eicar.com"
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    sample.write_bytes(eicar)
    try:
        assert sample.read_bytes() == eicar
    except OSError as exc:
        pytest.skip(f"host security software blocked access to the EICAR test fixture: {exc}")

    verdict = scan_path(sample, rules)

    assert verdict.status == "detected", verdict.reason
    assert verdict.action == "block"
    assert verdict.rule_id == "eicar-test-file"
