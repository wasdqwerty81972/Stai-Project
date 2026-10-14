"""Build a locally signed SVS Cyber package from a pinned YARA Forge ZIP.

The signing key must stay outside the repository. This package authenticates
the imported bytes to the SVS Cyber service; it does not transfer authorship
or upstream rule-signing authority to SVS Cyber.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


_CORE_RULE_PATH = "packages/core/yara-rules-core.yar"
_EXTENDED_RULE_PATH = "packages/extended/yara-rules-extended.yar"
_RULE_GROUP = re.compile(r"(?=/\*\s*\n \* YARA Rule Set)")
_REPOSITORY = re.compile(r"Repository Name:\s*([^\r\n]+)")
_DECLARATION = re.compile(r"(?m)^(?:(?:private|global)\s+)*rule\s+[A-Za-z_][A-Za-z0-9_]*\b")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_ARCHIVE_BYTES = 24 * 1024 * 1024
_MAX_RULE_SOURCE_BYTES = 24 * 1024 * 1024

# Keep this list deliberately small and require the expected license marker in
# each generated upstream source block. A license change fails the import.
_REDISTRIBUTABLE_SOURCES = {
    "DitekSHen": ("2-Clause BSD License", "BSD-2-Clause"),
    "ESET": ("Redistribution and use in source and binary forms", "LicenseRef-ESET-Malware-IOC"),
    "GCTI": (r"Apache License[\s\S]{0,100}Version 2\.0", "Apache-2.0"),
    "Trellix ARC": (r"Apache License[\s\S]{0,100}Version 2\.0", "Apache-2.0"),
    "Elceef": ("MIT License", "MIT"),
    "WithSecureLabs": ("BSD 2-Clause License", "BSD-2-Clause"),
    "LOLDrivers": (r"Apache License[\s\S]{0,100}Version 2\.0", "Apache-2.0"),
}

# Extended sources are selected by repository and an explicit license marker.
# NO LICENSE SET, non-commercial, and unknown licenses are intentionally omitted.
# Keep each upstream license block intact in the resulting YARA source.
_EXTENDED_REDISTRIBUTABLE_SOURCES = {
    **_REDISTRIBUTABLE_SOURCES,
    "ReversingLabs": (r"Permission is hereby granted[\s\S]{0,300}Software", "MIT"),
    "BinaryAlert": (r"Apache License[\s\S]{0,200}Version 2\.0", "Apache-2.0"),
    "FireEye-RT": (r"BSD 2-Clause License", "BSD-2-Clause"),
    "Volexity": (r"2-Clause BSD License", "BSD-2-Clause"),
    "JPCERTCC": (r"3-Clause BSD License", "BSD-3-Clause"),
    "Signature Base": (r"Detection Rule License \(DRL\) 1\.1", "DRL-1.1"),
    "SEKOIA": (r"Detection Rule License \(DRL\) 1\.1", "DRL-1.1"),
    "Dr4k0nia": (r"Detection Rule License \(DRL\) 1\.1", "DRL-1.1"),
    "Cod3nym": (r"Detection Rule License \(DRL\) 1\.1", "DRL-1.1"),
    "Synacktiv": (r"Detection Rule License \(DRL\) 1\.1", "DRL-1.1"),
    "CAPE": (r"GNU GENERAL PUBLIC LICENSE[\s\S]{0,200}Version 3", "GPL-3.0"),
    "craiu": (r"GNU GENERAL PUBLIC LICENSE[\s\S]{0,200}Version 3", "GPL-3.0"),
}


@dataclass(frozen=True)
class CoreBundle:
    source: str
    rule_count: int
    sources: tuple[str, ...]
    licenses: tuple[tuple[str, str], ...] = ()


def _validate_release(release: str, archive_sha256: str) -> None:
    if not release or not re.fullmatch(r"[0-9]{8}", release):
        raise ValueError("YARA Forge release must be an YYYYMMDD tag")
    if not _SHA256.fullmatch(archive_sha256):
        raise ValueError("upstream archive SHA-256 is invalid")


def _build_bundle(
    source: str,
    *,
    release: str,
    archive_sha256: str,
    allowed_sources: dict[str, tuple[str, str]],
    require_all: bool,
) -> CoreBundle:
    _validate_release(release, archive_sha256)
    parts = _RULE_GROUP.split(source)
    if len(parts) < 2 or 'import "pe"' not in parts[0]:
        raise ValueError("input is not a YARA Forge rules file")

    selected: list[str] = []
    names: list[str] = []
    licenses: list[tuple[str, str]] = []
    count = 0
    for group in parts[1:]:
        repository = _REPOSITORY.search(group)
        if not repository:
            raise ValueError("YARA Forge rule group has no repository name")
        name = repository.group(1).strip()
        expected = allowed_sources.get(name)
        if expected is None:
            continue
        license_region = group.split("LICENSE", 1)[1].split("*/", 1)[0] if "LICENSE" in group else ""
        if not re.search(expected[0], license_region, re.IGNORECASE) or "NO LICENSE SET" in license_region:
            raise ValueError(f"upstream license changed or is missing for {name}")
        group_count = len(_DECLARATION.findall(group))
        if group_count == 0:
            raise ValueError(f"licensed source {name} contains no YARA rules")
        count += group_count
        names.append(name)
        licenses.append((name, expected[1]))
        selected.append(group)

    if require_all:
        missing = set(allowed_sources) - set(names)
        if missing:
            raise ValueError(f"YARA Forge package is missing expected sources: {', '.join(sorted(missing))}")
    if not selected:
        raise ValueError("no explicitly licensed YARA Forge rule sources were selected")
    bundled_source = parts[0] + "".join(selected)
    if len(bundled_source.encode("utf-8")) > _MAX_RULE_SOURCE_BYTES:
        raise ValueError("selected YARA source exceeds the signed package limit")
    return CoreBundle(bundled_source, count, tuple(names), tuple(licenses))


def build_core_bundle(source: str, *, release: str, archive_sha256: str) -> CoreBundle:
    """Select only explicitly licensed sources from a YARA Forge core file."""
    return _build_bundle(
        source,
        release=release,
        archive_sha256=archive_sha256,
        allowed_sources=_REDISTRIBUTABLE_SOURCES,
        require_all=True,
    )


def build_extended_bundle(source: str, *, release: str, archive_sha256: str) -> CoreBundle:
    """Select extended sources with known redistribution terms and retain notices."""
    return _build_bundle(
        source,
        release=release,
        archive_sha256=archive_sha256,
        allowed_sources=_EXTENDED_REDISTRIBUTABLE_SOURCES,
        require_all=False,
    )


def _read_archive(path: Path, expected_sha256: str, *, tier: str) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise ValueError("YARA Forge archive SHA-256 does not match the pinned digest")
    with zipfile.ZipFile(path) as archive:
        rule_path = _EXTENDED_RULE_PATH if tier == "extended" else _CORE_RULE_PATH
        try:
            entry = archive.getinfo(rule_path)
        except KeyError as exc:
            raise ValueError(f"YARA Forge archive does not contain {tier} rules") from exc
        if entry.file_size > _MAX_ARCHIVE_BYTES:
            raise ValueError(f"YARA Forge {tier} file exceeds the input size limit")
        return archive.read(entry).decode("utf-8")


def build_signed_package(
    archive_path: Path,
    *,
    release: str,
    archive_sha256: str,
    private_key_path: Path,
    output_dir: Path,
    tier: str = "core",
) -> tuple[int, Path]:
    """Compile, sign, and write a YARA Forge rules package."""
    if tier not in {"core", "extended"}:
        raise ValueError("YARA Forge tier must be core or extended")
    source = _read_archive(archive_path, archive_sha256, tier=tier)
    builder = build_extended_bundle if tier == "extended" else build_core_bundle
    bundle = builder(source, release=release, archive_sha256=archive_sha256)

    try:
        import yara
    except ImportError as exc:
        raise RuntimeError("yara-python is required to validate the imported package") from exc
    yara.compile(source=bundle.source)

    key_bytes = private_key_path.read_bytes()
    private_key = serialization.load_pem_private_key(key_bytes, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("rules package signing key must be an unencrypted Ed25519 private key")
    manifest = json.dumps(
        {
            "version": f"svs-yara-forge-{tier}-{release}",
            "rules": [
                {
                    "id": f"yara-forge-{tier}",
                    "kind": "yara",
                    "value": bundle.source,
                    "action": "observe",
                    "confidence": "medium",
                    "count": bundle.rule_count,
                }
            ],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"
    signature_path = output_dir / "manifest.sig"
    public_key_path = output_dir / "trusted-rules.pub.pem"
    manifest_path.write_bytes(manifest)
    signature_path.write_bytes(private_key.sign(manifest))
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    (output_dir / "package-source.json").write_text(
        json.dumps(
            {
                "upstream": "https://github.com/YARAHQ/yara-forge",
                "release": release,
                "archive_sha256": archive_sha256,
                "included_sources": list(bundle.sources),
                "source_licenses": dict(bundle.licenses),
                "tier": tier,
                "included_rule_count": bundle.rule_count,
                "upstream_tier_rule_count": 10812 if tier == "extended" else None,
                "excluded_unlicensed_sources": True,
                "action": "observe",
                "confidence": "medium",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    license_lines = "\n".join(
        f"- {name}: {license_id}" for name, license_id in bundle.licenses
    )
    upstream_count = 10812 if tier == "extended" else bundle.rule_count
    (output_dir / "README.md").write_text(
        f"""# SVS Cyber YARA Forge {tier} rules

This package contains **{bundle.rule_count:,} compiled YARA rules** selected
from the YARA Forge {tier} release `{release}`. The upstream release lists
{upstream_count:,} rules for this tier; this package contains only source groups
with an explicit redistribution license marker. Groups with missing, unknown,
or restricted terms are omitted. See `package-source.json` for the exact
archive digest, included sources, and license identifiers.

## Included source groups and licenses

{license_lines}

Upstream source headers and license notices are kept in the signed manifest.
DRL 1.1 matches include their `author` metadata in the reported rule ID.

All imported rules use `observe` / `medium` behavior. A match is recorded for
review; it does not automatically block, terminate, or quarantine a file. The
bundle provides additional file-scan coverage, not real-time file-open
blocking or a vendor malware-reputation service.

The detached Ed25519 signature authenticates this package to a service build
that embeds the matching public key. It uses a local development trust anchor,
not a signature from YARA Forge, its upstream rule authors, Microsoft, or an
antivirus vendor. The private development key stays outside this repository
and must not be committed or distributed.
""",
        encoding="utf-8",
    )
    return bundle.rule_count, manifest_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--release", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--tier", choices=("core", "extended"), default="core")
    args = parser.parse_args()
    count, manifest = build_signed_package(
        args.archive,
        release=args.release,
        archive_sha256=args.archive_sha256,
        private_key_path=args.private_key,
        output_dir=args.output_dir,
        tier=args.tier,
    )
    print(f"Validated and signed {count} upstream YARA rules: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
