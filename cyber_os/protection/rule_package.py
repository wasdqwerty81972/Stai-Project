"""Verify signed, versioned detection rules before they can be activated."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import DetectionRule, RuleAction, RuleConfidence, RuleKind, RuleSet


_MAX_MANIFEST_BYTES = 10 * 1024 * 1024
_MAX_RULES = 100_000
_MAX_RULE_VALUE_CHARS = 256 * 1024
_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
_SHA256_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
_RULE_FIELDS = {"id", "kind", "value", "action", "confidence"}


class InvalidRulePackage(ValueError):
    """The package is malformed, unsupported, or failed signature checking."""


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidRulePackage(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _parse_manifest(raw_manifest: bytes) -> RuleSet:
    try:
        document = json.loads(
            raw_manifest.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
        )
    except InvalidRulePackage:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidRulePackage("manifest is not valid UTF-8 JSON") from exc

    if not isinstance(document, dict) or set(document) != {"version", "rules"}:
        raise InvalidRulePackage("manifest must contain only version and rules")

    version = document["version"]
    if not isinstance(version, str) or not _VERSION_PATTERN.fullmatch(version):
        raise InvalidRulePackage("manifest version is invalid")

    raw_rules = document["rules"]
    if not isinstance(raw_rules, list) or len(raw_rules) > _MAX_RULES:
        raise InvalidRulePackage("manifest rules must be a bounded array")

    rules: list[DetectionRule] = []
    seen_ids: set[str] = set()
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, dict) or set(raw_rule) != _RULE_FIELDS:
            raise InvalidRulePackage("rule has an invalid schema")

        rule_id = raw_rule["id"]
        kind = raw_rule["kind"]
        value = raw_rule["value"]
        action = raw_rule["action"]
        confidence = raw_rule["confidence"]
        if not isinstance(rule_id, str) or not _ID_PATTERN.fullmatch(rule_id):
            raise InvalidRulePackage("rule id is invalid")
        if rule_id in seen_ids:
            raise InvalidRulePackage(f"duplicate rule id: {rule_id}")
        seen_ids.add(rule_id)
        if kind not in ("sha256", "yara"):
            raise InvalidRulePackage(f"unsupported rule kind: {kind!r}")
        if action not in ("block", "observe"):
            raise InvalidRulePackage(f"unsupported rule action: {action!r}")
        if confidence not in ("high", "medium", "low"):
            raise InvalidRulePackage(f"unsupported rule confidence: {confidence!r}")
        if not isinstance(value, str) or not value or len(value) > _MAX_RULE_VALUE_CHARS:
            raise InvalidRulePackage("rule value is empty or exceeds the size limit")
        if kind == "sha256" and not _SHA256_PATTERN.fullmatch(value):
            raise InvalidRulePackage("sha256 rule must contain 64 lowercase hex characters")
        if action == "block" and confidence != "high":
            raise InvalidRulePackage("block rules require high confidence")

        rules.append(
            DetectionRule(
                id=rule_id,
                kind=kind,  # type: ignore[arg-type]
                value=value,
                action=action,  # type: ignore[arg-type]
                confidence=confidence,  # type: ignore[arg-type]
            )
        )

    return RuleSet(version=version, rules=tuple(rules))


class RulePackage:
    """Loader for manifests whose detached Ed25519 signature is trusted."""

    @staticmethod
    def load(manifest_path: Path, signature_path: Path, public_key: bytes) -> RuleSet:
        """Verify the exact manifest bytes, then validate and return its rules.

        The detached signature is the 64-byte Ed25519 signature over the exact
        UTF-8 manifest file contents. The caller supplies the trusted raw
        32-byte public key independently of the editable rule package.
        """

        try:
            with Path(manifest_path).open("rb") as manifest_file:
                raw_manifest = manifest_file.read(_MAX_MANIFEST_BYTES + 1)
            with Path(signature_path).open("rb") as signature_file:
                signature = signature_file.read(65)
        except OSError as exc:
            raise InvalidRulePackage("manifest or signature could not be read") from exc

        if len(raw_manifest) > _MAX_MANIFEST_BYTES:
            raise InvalidRulePackage("manifest exceeds the size limit")
        if len(signature) != 64:
            raise InvalidRulePackage("signature must be 64 bytes")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise InvalidRulePackage("trusted public key must be 32 raw bytes")

        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature,
                raw_manifest,
            )
        except (InvalidSignature, ValueError) as exc:
            raise InvalidRulePackage("manifest signature verification failed") from exc

        return _parse_manifest(raw_manifest)
