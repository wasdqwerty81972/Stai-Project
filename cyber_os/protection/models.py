"""Immutable contracts shared by the protection scanner and service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional


RuleKind = Literal["sha256", "yara"]
RuleAction = Literal["block", "observe"]
RuleConfidence = Literal["high", "medium", "low"]
VerdictStatus = Literal["clean", "detected", "unknown"]
VerdictAction = Literal["allow", "block"]


@dataclass(frozen=True, slots=True)
class DetectionRule:
    id: str
    kind: RuleKind
    value: str
    action: RuleAction
    confidence: RuleConfidence


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


@dataclass(frozen=True, slots=True)
class ScanProfile:
    """Resolved, allowlisted scan roots belonging to the enrolled Windows user."""

    owner_sid: str
    roots: tuple[tuple[str, str], ...]
    refreshed_at: str


@dataclass(frozen=True, slots=True)
class ScanRootSnapshot:
    """One root captured immutably when a scan job is created."""

    job_id: str
    folder_id: str
    path: str


@dataclass(frozen=True, slots=True)
class ScanSchedule:
    """One enrolled user's daily or weekly Quick Scan schedule."""

    owner_sid: str
    enabled: bool
    cadence: Literal["daily", "weekly"]
    local_time: str
    days_of_week: tuple[str, ...]
    last_run_date: Optional[str]
    last_job_id: Optional[str]
    last_result: Optional[str]
    next_run_local: Optional[str]
