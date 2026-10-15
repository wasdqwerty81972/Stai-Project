"""Bounded, fail-open file scanner for authenticated STAI rule packages."""

from __future__ import annotations

import hashlib
import math
import os
import stat
import time
from dataclasses import replace
from pathlib import Path
from typing import BinaryIO

from .models import DetectionRule, RuleSet, ScanReasonCode, ScanVerdict


_CHUNK_SIZE = 1024 * 1024
MAX_FILE_SIZE_BYTES = 256 * 1024 * 1024
DEFAULT_FILE_TIMEOUT_SECONDS = 30.0
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
SCANNER_ENGINE_VERSION = "1"


class _FileChanged(Exception):
    """The path or file metadata changed while the scan was in progress."""


class _YaraTimeout(Exception):
    """YARA did not finish within its configured time budget."""


class _YaraFailure(Exception):
    """YARA was unavailable or could not compile or match signed rules."""


def _check_yara_compile_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise _YaraTimeout("YARA compilation exhausted its time budget")


class _ScanBudgetExceeded(Exception):
    """A file exceeded a configured size or wall-clock scan budget."""

    def __init__(self, reason: str, reason_code: ScanReasonCode) -> None:
        super().__init__(reason)
        self.reason_code = reason_code


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


def _digest_stream(
    stream: BinaryIO,
    *,
    deadline: float,
    max_bytes: int,
) -> str:
    digest = hashlib.sha256()
    total_bytes = 0
    while True:
        chunk = stream.read(_CHUNK_SIZE)
        if time.monotonic() >= deadline:
            raise _ScanBudgetExceeded(
                "file scan exceeded its time budget", "time_budget_exceeded"
            )
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise _ScanBudgetExceeded(
                "file exceeds the maximum scan size", "oversized"
            )
        digest.update(chunk)
    return digest.hexdigest()


def _read_digest(
    path: Path,
    expected: tuple[int, int, int, int, int, int],
    *,
    deadline: float | None = None,
    max_bytes: int = MAX_FILE_SIZE_BYTES,
) -> str:
    deadline = deadline if deadline is not None else time.monotonic() + DEFAULT_FILE_TIMEOUT_SECONDS
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if _snapshot(before) != expected:
            raise _FileChanged("scan target changed before reading")
        digest = _digest_stream(stream, deadline=deadline, max_bytes=max_bytes)
        after = os.fstat(stream.fileno())
        if _snapshot(after) != expected:
            raise _FileChanged("scan target changed while reading")
    return digest


def _namespace(index: int) -> str:
    return f"stai_{index}"


class _RuleIndex:
    """Derived lookups for one rule set, built once instead of once per file.

    ``scan_path`` runs per file, so anything proportional to the rule count has
    to be hoisted out of it: the package validator admits up to 100k rules, and
    both the old linear SHA-256 sweep (~23 ms/file at that cap) and recompiling
    the YARA sources for every file dominated a full-system scan.
    """

    __slots__ = ("sha256", "yara", "_compiled", "_compile_error", "compiled_ids", "failed_ids")

    def __init__(self, rules: tuple[DetectionRule, ...]) -> None:
        sha256: dict[str, list[DetectionRule]] = {}
        yara_rules: list[DetectionRule] = []
        for rule in rules:
            if rule.kind == "sha256":
                sha256.setdefault(rule.value, []).append(rule)
            elif rule.kind == "yara":
                yara_rules.append(rule)
        self.sha256: dict[str, tuple[DetectionRule, ...]] = {
            digest: tuple(matches) for digest, matches in sha256.items()
        }
        self.yara: tuple[DetectionRule, ...] = tuple(yara_rules)
        self._compiled: object | None = None
        self._compile_error: _YaraFailure | None = None
        self.compiled_ids: tuple[str, ...] = ()
        self.failed_ids: tuple[str, ...] = ()

    def compiled_yara(self, *, deadline: float | None = None) -> object:
        """Compile the signed YARA sources once, skipping sources that fail.

        Compiling every source in one batch is the fast path. A single invalid
        source aborted that batch and silently disabled YARA matching for
        *every* rule, so a failed batch is retried rule by rule and the valid
        rules are kept. ``_YaraFailure`` is raised only when nothing compiles.
        """

        if self._compile_error is not None:
            raise self._compile_error
        if self._compiled is not None:
            return self._compiled
        try:
            self._compiled = self._compile(deadline=deadline)
        except _YaraFailure as exc:
            # Import availability and compile outcomes are deterministic for a
            # given rule set, so the failure is remembered instead of retried
            # for every scanned file.
            self._compile_error = exc
            raise
        return self._compiled

    def _compile(self, *, deadline: float | None = None) -> object:
        try:
            import yara
        except ImportError as exc:
            raise _YaraFailure("YARA runtime is unavailable") from exc

        sources = {
            _namespace(index): rule.value for index, rule in enumerate(self.yara)
        }
        _check_yara_compile_deadline(deadline)
        try:
            compiled = yara.compile(sources=sources, includes=False)
        except Exception:
            pass
        else:
            self.compiled_ids = tuple(rule.id for rule in self.yara)
            self.failed_ids = ()
            return compiled

        valid: dict[str, str] = {}
        compiled_ids: list[str] = []
        failed_ids: list[str] = []
        for index, rule in enumerate(self.yara):
            # A native compile cannot be interrupted, but do not start another
            # source once the scan budget has expired. Timeouts are not cached.
            _check_yara_compile_deadline(deadline)
            namespace = _namespace(index)
            try:
                yara.compile(sources={namespace: rule.value}, includes=False)
            except Exception:
                failed_ids.append(rule.id)
                continue
            valid[namespace] = rule.value
            compiled_ids.append(rule.id)

        _check_yara_compile_deadline(deadline)
        if not valid:
            raise _YaraFailure("signed YARA rules could not be compiled")
        try:
            compiled = yara.compile(sources=valid, includes=False)
        except Exception as exc:
            raise _YaraFailure("signed YARA rules could not be compiled") from exc
        self.compiled_ids = tuple(compiled_ids)
        self.failed_ids = tuple(failed_ids)
        return compiled


# Single-entry cache keyed on rule-set identity. Keying on equality instead
# would have to hash every rule on every scan, which costs more than the linear
# sweep it replaces. The tuple is held so its id can never be reused.
_rule_index_cache: tuple[tuple[DetectionRule, ...], _RuleIndex] | None = None


def rule_index(rules: tuple[DetectionRule, ...]) -> _RuleIndex:
    """Return the derived index for ``rules``, rebuilding only when it changes."""
    global _rule_index_cache
    cached = _rule_index_cache
    if cached is not None and cached[0] is rules:
        return cached[1]
    index = _RuleIndex(rules)
    _rule_index_cache = (rules, index)
    return index


def _match_yara(
    path: Path,
    rules: tuple[DetectionRule, ...],
    timeout_seconds: float,
) -> tuple[DetectionRule, ...]:
    index = rule_index(rules)
    if not index.yara:
        return ()

    deadline = time.monotonic() + timeout_seconds
    compiled = index.compiled_yara(deadline=deadline)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _YaraTimeout("YARA compilation exhausted its time budget")

    try:
        # YARA accepts whole seconds only. Round up to avoid disabling useful
        # subsecond scans, then reject any result that arrived after our deadline.
        matches = compiled.match(filepath=str(path), timeout=math.ceil(remaining))
    except Exception as exc:
        import yara

        yara_timeout = getattr(yara, "TimeoutError", None)
        if isinstance(exc, TimeoutError) or (
            isinstance(yara_timeout, type) and isinstance(exc, yara_timeout)
        ):
            raise _YaraTimeout("YARA match exceeded its time budget") from exc
        raise _YaraFailure("YARA scan failed") from exc

    if time.monotonic() >= deadline:
        raise _YaraTimeout("YARA match exceeded its time budget")

    rule_by_namespace = {
        _namespace(position): rule for position, rule in enumerate(index.yara)
    }
    matched_rules: list[DetectionRule] = []
    for match in matches:
        if match.namespace not in rule_by_namespace:
            continue
        bundle = rule_by_namespace[match.namespace]
        match_id = f"{bundle.id}:{match.rule}" if bundle.count > 1 else bundle.id
        metadata = getattr(match, "meta", {}) or {}
        author = metadata.get("author") or metadata.get("Author")
        if bundle.count > 1 and isinstance(author, str) and author.strip():
            # DRL 1.1 requires the rule author to be included in match messages.
            # The rule id is returned through the existing verdict/UI path.
            safe_author = " ".join(author.split())[:160]
            match_id = f"{match_id} (author: {safe_author})"
        matched_rules.append(replace(bundle, id=match_id, count=1))
    if index.failed_ids and not any(
        rule.action == "block" and rule.confidence == "high" for rule in matched_rules
    ):
        raise _YaraFailure(
            "some signed YARA sources could not be compiled; scan coverage is incomplete"
        )
    return tuple(matched_rules)


def _unknown(
    rule_version: str,
    reason: str,
    sha256: str | None = None,
    *,
    reason_code: ScanReasonCode = "analysis_unavailable",
) -> ScanVerdict:
    return ScanVerdict(
        status="unknown",
        action="allow",
        rule_id=None,
        rule_version=rule_version,
        sha256=sha256,
        reason=reason,
        reason_code=reason_code,
    )


def scan_path(
    path: Path,
    rules: RuleSet,
    *,
    yara_timeout_seconds: int = 5,
    max_file_bytes: int | None = None,
    file_timeout_seconds: float = DEFAULT_FILE_TIMEOUT_SECONDS,
) -> ScanVerdict:
    """Scan one regular file without following links or trusting unstable bytes.

    A file read, path race, invalid YARA source, missing YARA runtime, or YARA
    timeout produces an ``unknown``/``allow`` verdict. Blocking is limited to
    high-confidence block rules from the supplied rule set.

    Deadlines are cooperative: blocking OS reads and a native YARA compile
    cannot be interrupted. Fallback compilation checks the deadline between
    sources. YARA matching rounds its timeout up to whole seconds; results
    arriving after the deadline are not accepted as complete analysis.
    """

    if type(yara_timeout_seconds) is not int or not 1 <= yara_timeout_seconds <= 2_147_483_647:
        return _unknown(
            rules.version,
            "YARA timeout must be a positive bounded integer",
            reason_code="invalid_budget",
        )
    max_file_bytes = MAX_FILE_SIZE_BYTES if max_file_bytes is None else max_file_bytes
    try:
        valid_timeout = (
            type(file_timeout_seconds) in (int, float)
            and math.isfinite(file_timeout_seconds)
            and file_timeout_seconds > 0
        )
    except OverflowError:
        valid_timeout = False
    if type(max_file_bytes) is not int or max_file_bytes < 1 or not valid_timeout:
        return _unknown(
            rules.version,
            "file scan budgets must be positive",
            reason_code="invalid_budget",
        )

    target = Path(path)
    try:
        initial_snapshot = _snapshot(_safe_file_stat(target))
        if initial_snapshot[3] > max_file_bytes:
            raise _ScanBudgetExceeded(
                "file exceeds the maximum scan size", "oversized"
            )
        deadline = time.monotonic() + file_timeout_seconds
        digest = _read_digest(
            target,
            initial_snapshot,
            deadline=deadline,
            max_bytes=max_file_bytes,
        )
        after_hash_snapshot = _snapshot(_safe_file_stat(target))
        if after_hash_snapshot != initial_snapshot:
            raise _FileChanged("scan target changed after reading")
        yara_error: _YaraTimeout | _YaraFailure | None = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _YaraTimeout("file scan exceeded its time budget")
            yara_matches = _match_yara(target, rules.rules, min(yara_timeout_seconds, remaining))
            if time.monotonic() >= deadline:
                raise _YaraTimeout("file scan exceeded its time budget")
        except (_YaraTimeout, _YaraFailure) as exc:
            # An unavailable secondary matcher must not erase an already
            # verified exact-hash block. Preserve the error for unknown results.
            yara_matches = ()
            yara_error = exc
        final_snapshot = _snapshot(_safe_file_stat(target))
        if final_snapshot != initial_snapshot:
            raise _FileChanged("scan target changed during YARA matching")
    except _ScanBudgetExceeded as exc:
        return _unknown(rules.version, str(exc), reason_code=exc.reason_code)
    except _FileChanged:
        return _unknown(
            rules.version,
            "file changed or is not a safe regular file",
            reason_code="unstable_or_unsafe_file",
        )
    except OSError:
        return _unknown(
            rules.version,
            "file could not be read",
            locals().get("digest"),
            reason_code="read_error",
        )

    matching_rules = list(rule_index(rules.rules).sha256.get(digest, ()))
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
                reason_code="rule_match",
            )
        return _unknown(
            rules.version,
            str(yara_error),
            digest,
            reason_code=(
                "time_budget_exceeded"
                if isinstance(yara_error, _YaraTimeout)
                else "analysis_unavailable"
            ),
        )

    matching_rules.extend(yara_matches)
    if not matching_rules:
        return ScanVerdict(
            status="clean",
            action="allow",
            rule_id=None,
            rule_version=rules.version,
            sha256=digest,
            reason="no signed rule matched",
            reason_code="clean",
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
        reason_code="rule_match",
    )
