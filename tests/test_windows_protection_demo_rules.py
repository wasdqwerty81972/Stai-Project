from __future__ import annotations

import hashlib
from pathlib import Path

from cyber_os.protection.rule_package import RulePackage


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
