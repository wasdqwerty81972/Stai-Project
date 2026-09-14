"""
cyber_os/doom_loop_detector.py — SVS-Cyber Agent Runtime Resilience

Detects when the AI agent is caught in an execution loop, repeatedly calling the
same tool(s) with identical arguments or producing repetitive empty inputs.

Adapted from mature agent resilience architecture for SVS-Cyber.

Features:
- Two-tier response:
    - Warning threshold (3 consecutive identical calls): injects a corrective nudge prompt.
    - Halt threshold (5 consecutive identical calls): cleanly terminates the loop.
- Cosmetic input stripping: eliminates non-functional fields like 'brief', 'justification',
  'explanation' so semantic argument equality is properly identified.
- Empty input tracking: detects when an agent repeatedly emits empty arguments.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

DOOM_LOOP_WARNING_THRESHOLD = 3
DOOM_LOOP_HALT_THRESHOLD = 5
EMPTY_TOOL_INPUT_WARNING_THRESHOLD = 2
EMPTY_TOOL_INPUT_HALT_THRESHOLD = 4

# Cosmetic fields that vary each invocation without altering functional execution
COSMETIC_INPUT_FIELDS: Set[str] = {
    "brief",
    "justification",
    "explanation",
    "rationale",
    "comment",
    "display_text",
}


class DoomLoopSeverity(str, Enum):
    NONE = "none"
    WARNING = "warning"
    HALT = "halt"


class DoomLoopReason(str, Enum):
    REPEATED_TOOL_CALL = "repeated_tool_call"
    EMPTY_TOOL_INPUT = "empty_tool_input"


@dataclass
class DoomLoopResult:
    severity: DoomLoopSeverity = DoomLoopSeverity.NONE
    tool_names: List[str] = field(default_factory=list)
    consecutive_count: int = 0
    reason: Optional[DoomLoopReason] = None
    nudge_message: Optional[str] = None


def strip_cosmetic_fields(input_data: Any) -> Any:
    """Recursively strips cosmetic fields so identical executions produce identical fingerprints."""
    if not isinstance(input_data, dict):
        return input_data
    clean: Dict[str, Any] = {}
    for k, v in input_data.items():
        if k in COSMETIC_INPUT_FIELDS:
            continue
        if isinstance(v, dict):
            clean[k] = strip_cosmetic_fields(v)
        elif isinstance(v, list):
            clean[k] = [strip_cosmetic_fields(item) if isinstance(item, dict) else item for item in v]
        else:
            clean[k] = v
    return clean


def is_empty_tool_input(input_data: Any) -> bool:
    """Returns True if the tool argument payload is empty or only cosmetic."""
    if input_data is None:
        return True
    if not isinstance(input_data, dict):
        return False
    clean = strip_cosmetic_fields(input_data)
    return len(clean) == 0


def fingerprint_step(tool_name: str, arguments: Any) -> str:
    """Computes a deterministic hash of the tool name and normalized arguments."""
    clean_args = strip_cosmetic_fields(arguments or {})
    try:
        serialized = json.dumps(clean_args, sort_keys=True, default=str)
    except Exception:
        serialized = str(clean_args)
    payload = f"{tool_name}:{serialized}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class DoomLoopDetector:
    """Maintains sliding execution history and evaluates loop risk."""

    def __init__(
        self,
        warning_threshold: int = DOOM_LOOP_WARNING_THRESHOLD,
        halt_threshold: int = DOOM_LOOP_HALT_THRESHOLD,
    ) -> None:
        self.warning_threshold = warning_threshold
        self.halt_threshold = halt_threshold
        self.step_fingerprints: List[str] = []
        self.step_tools: List[str] = []
        self.step_empty_flags: List[bool] = []

    def record_step(self, tool_name: str, arguments: Any) -> DoomLoopResult:
        """Records a step and evaluates loop conditions."""
        fp = fingerprint_step(tool_name, arguments)
        is_empty = is_empty_tool_input(arguments)

        self.step_fingerprints.append(fp)
        self.step_tools.append(tool_name)
        self.step_empty_flags.append(is_empty)

        # 1. Check for consecutive identical calls
        consecutive_identical = 0
        for prior_fp in reversed(self.step_fingerprints):
            if prior_fp == fp:
                consecutive_identical += 1
            else:
                break

        if consecutive_identical >= self.halt_threshold:
            return DoomLoopResult(
                severity=DoomLoopSeverity.HALT,
                tool_names=[tool_name],
                consecutive_count=consecutive_identical,
                reason=DoomLoopReason.REPEATED_TOOL_CALL,
                nudge_message=(
                    f"Agent loop halted: tool '{tool_name}' was invoked {consecutive_identical} "
                    "times consecutively with identical arguments without making new progress."
                ),
            )

        if consecutive_identical >= self.warning_threshold:
            return DoomLoopResult(
                severity=DoomLoopSeverity.WARNING,
                tool_names=[tool_name],
                consecutive_count=consecutive_identical,
                reason=DoomLoopReason.REPEATED_TOOL_CALL,
                nudge_message=(
                    f"Notice: You have called '{tool_name}' with the same arguments {consecutive_identical} "
                    "times in a row. Stop repeating this action. Analyze the existing results, try a different "
                    "tool, or synthesize your findings for the user."
                ),
            )

        # 2. Check for trailing empty inputs
        trailing_empty = 0
        for flag in reversed(self.step_empty_flags):
            if flag:
                trailing_empty += 1
            else:
                break

        if trailing_empty >= EMPTY_TOOL_INPUT_HALT_THRESHOLD:
            return DoomLoopResult(
                severity=DoomLoopSeverity.HALT,
                tool_names=[tool_name],
                consecutive_count=trailing_empty,
                reason=DoomLoopReason.EMPTY_TOOL_INPUT,
                nudge_message="Agent loop halted: tools called repeatedly without required arguments.",
            )

        if trailing_empty >= EMPTY_TOOL_INPUT_WARNING_THRESHOLD:
            return DoomLoopResult(
                severity=DoomLoopSeverity.WARNING,
                tool_names=[tool_name],
                consecutive_count=trailing_empty,
                reason=DoomLoopReason.EMPTY_TOOL_INPUT,
                nudge_message="Notice: The last actions had empty arguments. Supply valid parameters or conclude your response.",
            )

        return DoomLoopResult(severity=DoomLoopSeverity.NONE)

    def reset(self) -> None:
        """Clears state for a fresh investigation turn."""
        self.step_fingerprints.clear()
        self.step_tools.clear()
        self.step_empty_flags.clear()
