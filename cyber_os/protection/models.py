"""Immutable contracts shared by the protection scanner and service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


RuleKind = Literal["sha256", "yara"]
RuleAction = Literal["block", "observe"]
RuleConfidence = Literal["high", "medium", "low"]
VerdictStatus = Literal["clean", "detected", "unknown"]
VerdictAction = Literal["allow", "block"]
ScanReasonCode = Literal[
    "clean",
    "rule_match",
    "analysis_unavailable",
    "invalid_budget",
    "oversized",
    "time_budget_exceeded",
    "unstable_or_unsafe_file",
    "read_error",
]


@dataclass(frozen=True, slots=True)
class DetectionRule:
    id: str
    kind: RuleKind
    value: str
    action: RuleAction
    confidence: RuleConfidence
    # A single signed YARA source bundle can contain many individual rules.
    # Hash rules and legacy packages default to one entry per rule.
    count: int = 1


@dataclass(frozen=True, slots=True)
class RuleSet:
    version: str
    rules: tuple[DetectionRule, ...]


@dataclass(frozen=True, slots=True)
class ScanVerdict:
    status: VerdictStatus
    action: VerdictAction
    rule_id: str | None
    rule_version: str
    sha256: str | None
    reason: str
    # Machine-readable reason for unknown outcomes so callers never infer
    # that an unread/unsupported file was clean from the human message.
    reason_code: ScanReasonCode = "analysis_unavailable"
    intel_evidence: "ThreatIntelEvidence | None" = None


@dataclass(frozen=True, slots=True)
class ThreatIntelEvidence:
    """Exact-file hash evidence attached to a scan without granting a verdict."""

    indicator_type: str
    indicator_value: str
    source: str
    verification: str
    confidence: int
    severity: str
    feed_version: str
    first_seen: str
    last_seen: str
    freshness: str
    corroborations: int
    block_eligible: bool = False
    decision_reason: str = ""

    def __post_init__(self) -> None:
        if self.indicator_type != "sha256":
            raise ValueError("file scan evidence must be an exact SHA-256 indicator")
        if len(self.indicator_value) != 64 or any(c not in "0123456789abcdef" for c in self.indicator_value.lower()):
            raise ValueError("indicator_value must be a SHA-256 hex digest")
        if not 0 <= self.confidence <= 100:
            raise ValueError("confidence must be between 0 and 100")
        if self.corroborations < 1:
            raise ValueError("corroborations must be at least 1")
        for name in ("source", "verification", "severity", "feed_version", "freshness", "decision_reason"):
            if len(getattr(self, name)) > 256:
                raise ValueError(f"{name} exceeds 256 characters")
