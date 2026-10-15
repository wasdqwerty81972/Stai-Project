"""Resource limits for importing untrusted rule archives (no malware samples)."""

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from scripts import build_yara_forge_package as builder


def _archive(tmp_path: Path, payload: bytes) -> tuple[Path, str]:
    path = tmp_path / "rules.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(builder._CORE_RULE_PATH, payload)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_rejects_oversized_archive_before_reading_it(tmp_path, monkeypatch):
    path = tmp_path / "oversized.zip"
    path.write_bytes(b"x" * 65)
    monkeypatch.setattr(builder, "_MAX_ARCHIVE_BYTES", 64)
    with pytest.raises(ValueError, match="archive exceeds"):
        builder._read_archive(path, "0" * 64, tier="core")


def test_archive_hashing_does_not_load_entire_archive(tmp_path, monkeypatch):
    path, digest = _archive(tmp_path, b' import "pe"\n')
    def reject_read_bytes(self):
        raise AssertionError("archive must be hashed through bounded streaming reads")
    monkeypatch.setattr(Path, "read_bytes", reject_read_bytes)
    assert builder._read_archive(path, digest, tier="core") == ' import "pe"\n'


def test_rejects_oversized_expanded_rule_source(tmp_path, monkeypatch):
    path, digest = _archive(tmp_path, b"a" * 65)
    monkeypatch.setattr(builder, "_MAX_RULE_SOURCE_BYTES", 64)
    with pytest.raises(ValueError, match="file exceeds"):
        builder._read_archive(path, digest, tier="core")


def test_bounds_actual_decompression_even_if_metadata_understates_size(tmp_path, monkeypatch):
    path, digest = _archive(tmp_path, b"safe")
    monkeypatch.setattr(builder, "_MAX_RULE_SOURCE_BYTES", 64)
    monkeypatch.setattr(zipfile.ZipFile, "open", lambda *args, **kwargs: io.BytesIO(b"x" * 65))
    with pytest.raises(ValueError, match="file exceeds"):
        builder._read_archive(path, digest, tier="core")


def test_preserves_pinned_digest_verification(tmp_path):
    path, _ = _archive(tmp_path, b"safe")
    with pytest.raises(ValueError, match="pinned digest"):
        builder._read_archive(path, "0" * 64, tier="core")


def test_signed_builder_rejects_external_yara_includes(tmp_path, monkeypatch):
    yara = pytest.importorskip("yara")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    external = tmp_path / "unsigned.yar"
    external.write_text("rule UnsignedLocalRule { condition: true }", encoding="utf-8")
    source = f"include {json.dumps(external.as_posix())}\n"
    path, digest = _archive(tmp_path, source.encode("utf-8"))
    monkeypatch.setattr(
        builder, "build_core_bundle",
        lambda *args, **kwargs: builder.CoreBundle(source, 1, ("fixture",)),
    )
    private_key = tmp_path / "ephemeral.pem"
    private_key.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    output = tmp_path / "package"
    with pytest.raises(yara.SyntaxError):
        builder.build_signed_package(
            path, release="20261015", archive_sha256=digest,
            private_key_path=private_key, output_dir=output,
        )
    assert not (output / "manifest.json").exists()
    assert not (output / "manifest.sig").exists()


def test_historical_hash_catalogue_has_complete_provenance_and_safe_actions():
    from cyber_os.protection.rule_package import _parse_manifest

    directory = Path(__file__).parents[1] / "cyber_os/protection/rule_candidates/truebot-reference-20261015"
    rules = _parse_manifest((directory / "manifest.json").read_bytes())
    provenance = json.loads((directory / "provenance.json").read_text(encoding="utf-8"))
    assert len(rules.rules) == 5
    assert len({rule.value for rule in rules.rules}) == 5
    assert all(rule.kind == "sha256" and rule.action == "observe" and rule.confidence == "medium" for rule in rules.rules)
    assert {rule.id for rule in rules.rules} == {
        rule_id for source in provenance["sources"] for rule_id in source["rule_ids"]
    }
    assert provenance["first_seen"] is None and provenance["last_seen"] is None
    assert not (directory / "manifest.sig").exists()


def test_inert_examples_detect_only_the_intended_markers():
    yara = pytest.importorskip("yara")
    from cyber_os.protection.rule_package import _parse_manifest

    directory = Path(__file__).parents[1] / "examples/reference-rules"
    rules = _parse_manifest((directory / "manifest.json").read_bytes())
    for rule, fixture in zip(rules.rules, ("marker-text.txt", "marker-pair.txt", "marker-header.txt"), strict=True):
        compiled = yara.compile(source=rule.value)
        assert compiled.match(data=(directory / fixture).read_bytes())
        assert not compiled.match(data=(directory / "benign.txt").read_bytes())
        assert not compiled.match(data=b"x" * 4096 + (directory / fixture).read_bytes())
    pair = yara.compile(source=rules.rules[1].value)
    assert not pair.match(data=b"STAI_EXAMPLE_PAIR_ALPHA_V1")
    header = yara.compile(source=rules.rules[2].value)
    assert not header.match(data=b"xSTAI_EXAMPLE_HEADER_V1")
