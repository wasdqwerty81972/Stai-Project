from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyber_os.protection.models import DetectionRule, RuleSet
from cyber_os.protection.rule_package import RulePackage
from cyber_os.protection.scanner import scan_path
from scripts.build_yara_forge_package import build_core_bundle, build_extended_bundle


def _signed_package(tmp_path: Path, rules: list[dict[str, object]]) -> RuleSet:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    manifest = json.dumps(
        {"version": "yara-forge-test", "rules": rules},
        separators=(",", ":"),
    ).encode("utf-8")
    manifest_path = tmp_path / "manifest.json"
    signature_path = tmp_path / "manifest.sig"
    manifest_path.write_bytes(manifest)
    signature_path.write_bytes(private_key.sign(manifest))
    return RulePackage.load(manifest_path, signature_path, public_key)


def test_signed_yara_bundle_compiles_and_reports_the_matching_rule_name(
    tmp_path: Path,
) -> None:
    pytest.importorskip("yara")
    rules = _signed_package(
        tmp_path,
        [
            {
                "id": "yara-forge-core",
                "kind": "yara",
                "value": (
                    'rule Community_Test_Signature { meta: author = "SVS Test Author" strings: '
                    '$marker = "SVS-CYBER-YARA-TEST-MARKER" ascii '
                    'condition: $marker }'
                ),
                "action": "observe",
                "confidence": "medium",
                "count": 17,
            }
        ],
    )
    sample = tmp_path / "sample.txt"
    sample.write_text("harmless fixture SVS-CYBER-YARA-TEST-MARKER", encoding="ascii")

    verdict = scan_path(sample, rules)

    assert rules.rules[0].count == 17
    assert verdict.status == "detected"
    assert verdict.action == "allow"
    assert verdict.rule_id == (
        "yara-forge-core:Community_Test_Signature (author: SVS Test Author)"
    )


def test_core_bundle_keeps_only_explicitly_licensed_sources() -> None:
    source_licenses = {
        "DitekSHen": "The 2-Clause BSD License",
        "ESET": "Redistribution and use in source and binary forms",
        "GCTI": "Apache License Version 2.0",
        "Trellix ARC": "Apache License Version 2.0",
        "Elceef": "MIT License",
        "WithSecureLabs": "BSD 2-Clause License",
        "LOLDrivers": "Apache License Version 2.0",
    }
    groups = [
        f"/*\n * YARA Rule Set\n * Repository Name: {name}\n * LICENSE\n * {license_text}\n */\n"
        f"rule {name.replace(' ', '_')}_Test {{ condition: true }}\n"
        for name, license_text in source_licenses.items()
    ]
    fixture = (
        'import "pe"\n'
        + "".join(groups)
        + "/*\n * YARA Rule Set\n * Repository Name: UnlicensedSource\n"
        " * LICENSE\n * NO LICENSE SET\n */\n"
        "rule Unlicensed_Test { condition: true }\n"
    )

    bundle = build_core_bundle(fixture, release="20261011", archive_sha256="b" * 64)

    assert bundle.rule_count == 7
    assert bundle.sources == tuple(source_licenses)
    assert "DitekSHen_Test" in bundle.source
    assert "Unlicensed_Test" not in bundle.source


def test_bundled_core_manifest_is_signed_and_compiles() -> None:
    yara = pytest.importorskip("yara")
    package_dir = (
        Path(__file__).parents[1]
        / "windows_protection"
        / "installer"
        / "rules"
        / "yara-forge-core-20261011"
    )
    public_key = serialization.load_pem_public_key(
        (package_dir / "trusted-rules.pub.pem").read_bytes()
    ).public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    rules = RulePackage.load(
        package_dir / "manifest.json",
        package_dir / "manifest.sig",
        public_key,
    )
    compiled = yara.compile(source=rules.rules[0].value)

    assert rules.version == "svs-yara-forge-core-20261011"
    assert rules.rules[0].count == 898
    assert len(compiled.match(data=b"harmless signed rule package check")) == 0


def test_bundled_extended_manifest_is_signed_and_compiles() -> None:
    yara = pytest.importorskip("yara")
    package_dir = (
        Path(__file__).parents[1]
        / "windows_protection"
        / "installer"
        / "rules"
        / "yara-forge-extended-20261011"
    )
    public_key = serialization.load_pem_public_key(
        (package_dir / "trusted-rules.pub.pem").read_bytes()
    ).public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    rules = RulePackage.load(
        package_dir / "manifest.json",
        package_dir / "manifest.sig",
        public_key,
    )
    compiled = yara.compile(source=rules.rules[0].value)
    actual_count = sum(1 for _ in compiled)

    assert rules.version == "svs-yara-forge-extended-20261011"
    assert rules.rules[0].count == 8583
    assert actual_count == rules.rules[0].count
    assert len(compiled.match(data=b"harmless signed extended rule package check")) == 0


def test_extended_bundle_includes_large_explicitly_licensed_sets_and_excludes_unknown() -> None:
    groups = [
        "/*\n * YARA Rule Set\n * Repository Name: Signature Base\n"
        " * LICENSE\n * # Detection Rule License (DRL) 1.1\n */\n"
        "rule Signature_Test { meta: author = \"Ada\" condition: true }\n",
        "/*\n * YARA Rule Set\n * Repository Name: ReversingLabs\n"
        " * LICENSE\n * Permission is hereby granted, free of charge, to any person obtaining this software\n */\n"
        "rule RL_Test { condition: true }\n",
        "/*\n * YARA Rule Set\n * Repository Name: UnlicensedSource\n"
        " * LICENSE\n * NO LICENSE SET\n */\n"
        "rule Unlicensed_Test { condition: true }\n",
    ]
    fixture = 'import "pe"\n' + "".join(groups)

    bundle = build_extended_bundle(fixture, release="20261011", archive_sha256="b" * 64)

    assert bundle.rule_count == 2
    assert bundle.sources == ("Signature Base", "ReversingLabs")
    assert "Signature_Test" in bundle.source
    assert "RL_Test" in bundle.source
    assert "Unlicensed_Test" not in bundle.source
