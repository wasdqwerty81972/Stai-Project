"""Bounded, fail-open file scanner for authenticated STAI rule packages."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import BinaryIO

from .models import DetectionRule, RuleSet, ScanVerdict


_CHUNK_SIZE = 1024 * 1024
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
SCANNER_ENGINE_VERSION = "1"


class _FileChanged(Exception):
    """The path or file metadata changed while the scan was in progress."""


class _YaraTimeout(Exception):
    """YARA did not finish within its configured time budget."""


class _YaraFailure(Exception):
    """YARA was unavailable or could not compile or match signed rules."""


def _snapshot(file_stat: os.stat_result) -> tuple[int, int, int, int, int, int]:
    # Compare only the file *type* bits (S_IFMT), not the permission/execute
    # bits. On Windows ``os.stat`` by path synthesizes execute bits (0o111) for
    # executable extensions (.exe/.bat/.cmd/.com) while ``os.fstat`` by handle
    # cannot (it has no filename), so including the full mode spuriously
    # reports every executable as "changed" between the path-stat and the
    # in-read handle-stat -- which would fail-open (unknown/allow) on exactly
    # the files an antivirus most needs to scan. The type bits are consistent
    # across stat/fstat and are what the integrity check actually cares about.
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        stat.S_IFMT(file_stat.st_mode),
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def _safe_file_stat(path: Path) -> os.stat_result:
    file_stat = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(file_stat.st_mode):
        raise _FileChanged("scan target is not a regular file")
    if getattr(file_stat, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise _FileChanged("scan target is a reparse point")
    return file_stat


def _digest_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(_CHUNK_SIZE):
        digest.update(chunk)
    return digest.hexdigest()


def _read_digest(path: Path, expected: tuple[int, int, int, int, int, int]) -> str:
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if _snapshot(before) != expected:
            raise _FileChanged("scan target changed before reading")
        digest = _digest_stream(stream)
        after = os.fstat(stream.fileno())
        if _snapshot(after) != expected:
            raise _FileChanged("scan target changed while reading")
    return digest


def _match_yara(
    path: Path,
    rules: tuple[DetectionRule, ...],
    timeout_seconds: int,
) -> tuple[DetectionRule, ...]:
    yara_rules = tuple(rule for rule in rules if rule.kind == "yara")
    if not yara_rules:
        return ()

    try:
        import yara
    except ImportError as exc:
        raise _YaraFailure("YARA runtime is unavailable") from exc

    sources = {f"stai_{index}": rule.value for index, rule in enumerate(yara_rules)}
    try:
        compiled = yara.compile(sources=sources)
    except Exception as exc:
        raise _YaraFailure("signed YARA rules could not be compiled") from exc

    try:
        matches = compiled.match(filepath=str(path), timeout=timeout_seconds)
    except Exception as exc:
        yara_timeout = getattr(yara, "TimeoutError", None)
        if isinstance(exc, TimeoutError) or (
            isinstance(yara_timeout, type) and isinstance(exc, yara_timeout)
        ):
            raise _YaraTimeout("YARA match exceeded its time budget") from exc
        raise _YaraFailure("YARA scan failed") from exc

    matched_namespaces = {match.namespace for match in matches}
    return tuple(
        rule
        for index, rule in enumerate(yara_rules)
        if f"stai_{index}" in matched_namespaces
    )


def _unknown(rule_version: str, reason: str, sha256: str | None = None) -> ScanVerdict:
    return ScanVerdict(
        status="unknown",
        action="allow",
        rule_id=None,
        rule_version=rule_version,
        sha256=sha256,
        reason=reason,
    )


def scan_path(
    path: Path,
    rules: RuleSet,
    *,
    yara_timeout_seconds: int = 5,
) -> ScanVerdict:
    """Scan one regular file without following links or trusting unstable bytes.

    A file read, path race, invalid YARA source, missing YARA runtime, or YARA
    timeout produces an ``unknown``/``allow`` verdict. Blocking is limited to
    high-confidence block rules from the supplied rule set.
    """

    if yara_timeout_seconds < 1:
        return _unknown(rules.version, "YARA timeout must be at least one second")

    target = Path(path)
    try:
        initial_snapshot = _snapshot(_safe_file_stat(target))
        digest = _read_digest(target, initial_snapshot)
        after_hash_snapshot = _snapshot(_safe_file_stat(target))
        if after_hash_snapshot != initial_snapshot:
            raise _FileChanged("scan target changed after reading")
        yara_error: _YaraTimeout | _YaraFailure | None = None
        try:
            yara_matches = _match_yara(target, rules.rules, yara_timeout_seconds)
        except (_YaraTimeout, _YaraFailure) as exc:
            # An unavailable secondary matcher must not erase an already
            # verified exact-hash block. Preserve the error for unknown results.
            yara_matches = ()
            yara_error = exc
        final_snapshot = _snapshot(_safe_file_stat(target))
        if final_snapshot != initial_snapshot:
            raise _FileChanged("scan target changed during YARA matching")
    except _FileChanged:
        return _unknown(rules.version, "file changed or is not a safe regular file")
    except OSError:
        return _unknown(rules.version, "file could not be read", locals().get("digest"))

    matching_rules = [
        rule
        for rule in rules.rules
        if rule.kind == "sha256" and rule.value == digest
    ]
    if yara_error is not None:
        blocking_hash_rule = next(
            (
                rule
                for rule in matching_rules
                if rule.action == "block" and rule.confidence == "high"
            ),
            None,
        )
        if blocking_hash_rule is not None:
            return ScanVerdict(
                status="detected",
                action="block",
                rule_id=blocking_hash_rule.id,
                rule_version=rules.version,
                sha256=digest,
                reason="high-confidence SHA-256 block rule matched; YARA unavailable",
            )
        return _unknown(rules.version, str(yara_error), digest)

    matching_rules.extend(yara_matches)
    if not matching_rules:
        return ScanVerdict(
            status="clean",
            action="allow",
            rule_id=None,
            rule_version=rules.version,
            sha256=digest,
            reason="no signed rule matched",
        )

    blocking_rule = next(
        (
            rule
            for rule in matching_rules
            if rule.action == "block" and rule.confidence == "high"
        ),
        None,
    )
    selected_rule = blocking_rule or matching_rules[0]
    return ScanVerdict(
        status="detected",
        action="block" if blocking_rule else "allow",
        rule_id=selected_rule.id,
        rule_version=rules.version,
        sha256=digest,
        reason=(
            "high-confidence block rule matched"
            if blocking_rule
            else "observe rule matched"
        ),
    )
