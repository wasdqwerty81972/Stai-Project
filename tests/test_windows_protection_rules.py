from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyber_os.protection.models import DetectionRule
from cyber_os.protection.rule_package import InvalidRulePackage, RulePackage


def _write_signed_package(
    directory: Path,
    manifest: bytes | None = None,
) -> tuple[Path, Path, bytes, bytes]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    manifest = manifest or json.dumps(
        {
            "version": "test-1",
            "rules": [
                {
                    "id": "hash-1",
                    "kind": "sha256",
                    "value": "a" * 64,
                    "action": "block",
                    "confidence": "high",
                }
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    manifest_path = directory / "manifest.json"
    signature_path = directory / "manifest.sig"
    manifest_path.write_bytes(manifest)
    signature_path.write_bytes(private_key.sign(manifest))
    return manifest_path, signature_path, public_key, manifest


def test_signed_manifest_loads_and_preserves_rule_version(tmp_path: Path) -> None:
    manifest_path, signature_path, public_key, _ = _write_signed_package(tmp_path)

    loaded = RulePackage.load(manifest_path, signature_path, public_key)

    assert loaded.version == "test-1"
    assert loaded.rules == (
        DetectionRule(
            id="hash-1",
            kind="sha256",
            value="a" * 64,
            action="block",
            confidence="high",
        ),
    )


def test_tampered_manifest_is_rejected(tmp_path: Path) -> None:
    manifest_path, signature_path, public_key, manifest = _write_signed_package(tmp_path)
    manifest_path.write_bytes(manifest.replace(b"test-1", b"test-2"))

    with pytest.raises(InvalidRulePackage):
        RulePackage.load(manifest_path, signature_path, public_key)


@pytest.mark.parametrize(
    "rule",
    [
        {
            "id": "bad-hash",
            "kind": "sha256",
            "value": "not-a-sha256",
            "action": "block",
            "confidence": "high",
        },
        {
            "id": "weak-block",
            "kind": "sha256",
            "value": "a" * 64,
            "action": "block",
            "confidence": "medium",
        },
        {
            "id": "unknown-field",
            "kind": "sha256",
            "value": "a" * 64,
            "action": "observe",
            "confidence": "low",
            "shell_command": "ignored",
        },
    ],
)
def test_invalid_rule_and_block_without_high_confidence_are_rejected(
    tmp_path: Path,
    rule: dict[str, str],
) -> None:
    manifest = json.dumps(
        {"version": "test-invalid", "rules": [rule]}, separators=(",", ":")
    ).encode("utf-8")
    manifest_path, signature_path, public_key, _ = _write_signed_package(
        tmp_path,
        manifest,
    )

    with pytest.raises(InvalidRulePackage):
        RulePackage.load(manifest_path, signature_path, public_key)


def test_duplicate_json_fields_are_rejected(tmp_path: Path) -> None:
    manifest = (
        b'{"version":"test-1","version":"attacker",'
        b'"rules":[{"id":"observe-1","kind":"sha256",'
        b'"value":"' + b"a" * 64 + b'","action":"observe","confidence":"low"}]}'
    )
    manifest_path, signature_path, public_key, _ = _write_signed_package(
        tmp_path,
        manifest,
    )

    with pytest.raises(InvalidRulePackage):
        RulePackage.load(manifest_path, signature_path, public_key)
