"""
cyber_os/stop_conditions.py — SVS-Cyber Agent Runtime Stop Conditions

Provides explicit stop condition evaluators for the multi-step agent loop.
Prevents infinite loops, runaway token consumption, execution timeouts,
and handles clean termination.

Adapted from mature agent stop-condition architecture for SVS-Cyber.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class FinishReason(str, Enum):
    COMPLETE = "complete"
    STEP_LIMIT = "step_limit"
    ELAPSED_TIMEOUT = "elapsed_timeout"
    DOOM_LOOP = "doom_loop"
    TOKEN_LIMIT = "token_limit"
    BUDGET_LIMIT = "budget_limit"
    USER_CANCELLED = "user_cancelled"
    ERROR = "error"


class StopConditions:
    """Evaluates whether the agent loop should continue or terminate."""

    def __init__(
        self,
        max_steps: int = 15,
        max_elapsed_seconds: float = 300.0,
        max_tokens: int = 40_000,
    ) -> None:
        self.max_steps = max_steps
        self.max_elapsed_seconds = max_elapsed_seconds
        self.max_tokens = max_tokens
        self.start_time = time.time()
        self.steps_executed = 0
        self.estimated_tokens = 0
        self.finish_reason: Optional[FinishReason] = None
        self.finish_message: Optional[str] = None

    def record_step(self, tokens_used: int = 0) -> None:
        """Increments step count and updates estimated token expenditure."""
        self.steps_executed += 1
        self.estimated_tokens += tokens_used

    def should_stop(self, is_cancelled: bool = False, doom_loop_halt: bool = False) -> bool:
        """Returns True if any stop condition has fired."""
        if is_cancelled:
            self.finish_reason = FinishReason.USER_CANCELLED
            self.finish_message = "Investigation cancelled by user."
            return True

        if doom_loop_halt:
            self.finish_reason = FinishReason.DOOM_LOOP
            self.finish_message = "Agent halted to prevent repetitive doom loop."
            return True

        if self.steps_executed >= self.max_steps:
            self.finish_reason = FinishReason.STEP_LIMIT
            self.finish_message = f"Reached maximum allowed execution steps ({self.max_steps})."
            return True

        elapsed = time.time() - self.start_time
        if elapsed >= self.max_elapsed_seconds:
            self.finish_reason = FinishReason.ELAPSED_TIMEOUT
            self.finish_message = f"Investigation exceeded maximum allowed duration ({self.max_elapsed_seconds:.0f}s)."
            return True

        if self.estimated_tokens >= self.max_tokens:
            self.finish_reason = FinishReason.TOKEN_LIMIT
            self.finish_message = f"Context window token threshold exceeded ({self.estimated_tokens}/{self.max_tokens})."
            return True

        return False

    def reset(self) -> None:
        """Resets tracking for a new execution turn."""
        self.start_time = time.time()
        self.steps_executed = 0
        self.estimated_tokens = 0
        self.finish_reason = None
        self.finish_message = None
