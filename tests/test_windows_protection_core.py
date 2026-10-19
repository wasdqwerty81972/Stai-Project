"""Core integration test (plan Task 4).

Exercises signed rule-package verification, deterministic scanning, and
durable outcome records together -- the smallest end-to-end slice of the
protection core that does not need a driver or an AI runtime.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cyber_os.protection.models import RuleSet
from cyber_os.protection.rule_package import RulePackage
from cyber_os.protection.scanner import scan_path
from cyber_os.protection.service import ProtectionConfig, ProtectionService
from cyber_os.protection.store import ProtectionStore

_MARKER = b"STAI inert antivirus test marker"


def _signed_block_ruleset(directory: Path, content: bytes) -> RuleSet:
    """Build and load a signed single-hash block package, verifying its signature."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    manifest = json.dumps(
        {
            "version": "pack-1",
            "rules": [
                {
                    "id": "hash-1",
                    "kind": "sha256",
                    "value": hashlib.sha256(content).hexdigest(),
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
    return RulePackage.load(manifest_path, signature_path, public_key)


def test_signed_detection_is_durable_and_reproducible(tmp_path: Path) -> None:
    rules = _signed_block_ruleset(tmp_path, _MARKER)
    assert rules.version == "pack-1"

    sample = tmp_path / "sample.exe"
    sample.write_bytes(_MARKER)

    store = ProtectionStore(tmp_path / "p.db")
    service = ProtectionService(
        ProtectionConfig(quarantine_root=tmp_path / "quar", rules=rules, store=store)
    )

    first = service.scan_file(sample)
    assert (first.status, first.action, first.rule_id) == ("detected", "block", "hash-1")
    assert not sample.exists()

    # Durable: a fresh store over the same database still sees the detection.
    reopened = ProtectionStore(tmp_path / "p.db")
    threats = reopened.list_threats()
    assert len(threats) == 1
    assert threats[0].rule_id == "hash-1"
    assert threats[0].sha256 == hashlib.sha256(_MARKER).hexdigest()
    counts = reopened.get_status().counts
    assert counts["detected"] == 1
    assert counts["blocked"] == 0  # no denied kernel I/O happened
    assert counts["quarantined"] == 1

    # Reproducible: scanning the same bytes against the same rules is deterministic.
    sample_again = tmp_path / "sample-again.exe"
    sample_again.write_bytes(_MARKER)
    second = scan_path(sample_again, rules)
    assert (second.status, second.action, second.rule_id, second.sha256) == (
        first.status,
        first.action,
        first.rule_id,
        first.sha256,
    )


def test_unknown_verdict_never_creates_blocked_count(tmp_path: Path) -> None:
    rules = _signed_block_ruleset(tmp_path, _MARKER)
    store = ProtectionStore(tmp_path / "p.db")
    service = ProtectionService(
        ProtectionConfig(quarantine_root=tmp_path / "quar", rules=rules, store=store)
    )

    # A directory is not a safe regular file -> the scanner must return
    # unknown/allow (fail-open), never a detection or a block.
    not_a_file = tmp_path / "a_directory"
    not_a_file.mkdir()

    verdict = service.scan_file(not_a_file)

    assert verdict.status == "unknown"
    assert verdict.action == "allow"
    counts = store.get_status().counts
    assert counts == {"detected": 0, "blocked": 0, "quarantined": 0}
