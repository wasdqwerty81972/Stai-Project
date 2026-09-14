"""
subagents/base.py — Base Subagent Class

Common contract and execution interface for both core task workers
and SVS-Cyber defensive specialists.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from subagents.contracts import (
    SubagentCapabilityBundle,
    SubagentContextRef,
    SubagentProfile,
    SubagentStatus,
    SubagentStructuredResult,
    SubagentTaskRequest,
    SubagentVerdict,
    ValidationConfidence,
)
from ui.event_bus import AgentEvent, event_bus


class BaseSubagent(ABC):
    """Abstract base class for all SVS-Cyber subagents."""

    profile: SubagentProfile
    name: str
    icon: str
    description: str
    allowed_tools: List[str]
    capability_bundles: List[SubagentCapabilityBundle]
    max_steps: int = 15

    def __init__(self, agent: Any = None) -> None:
        self.agent = agent

    @abstractmethod
    def get_system_prompt(self, task: SubagentTaskRequest) -> str:
        """Returns the specialized role system prompt for this subagent."""
        raise NotImplementedError

    def build_user_prompt(self, task: SubagentTaskRequest) -> str:
        """Builds the task execution prompt with bounded parent context refs."""
        lines = [
            f"DELEGATED TASK: {task.objective}",
            "",
            "SUCCESS CRITERIA:",
        ]
        for i, sc in enumerate(task.success_criteria, 1):
            lines.append(f"{i}. {sc}")

        if task.context_refs:
            lines.append("\nPARENT INVESTIGATION REFERENCES:")
            for ref in task.context_refs:
                lines.append(f"[{ref.label}]:\n{ref.content}")

        lines.extend([
            "",
            "INSTRUCTIONS:",
            "- Confine your analysis strictly to the stated objective and references.",
            "- Execute only your authorized tools.",
            "- Return a clear conclusion with verdict (CONFIRMED, REJECTED, INCONCLUSIVE, or COMPLETED), confidence, evidence, and findings.",
        ])
        return "\n".join(lines)

    def execute(self, task: SubagentTaskRequest) -> SubagentStructuredResult:
        """Executes the subagent task and returns a structured settlement result."""
        start_time = time.time()
        
        # Publish start event
        event_bus.publish(
            AgentEvent(
                type="subagent_started",
                status="running",
                message=f"[{self.name}] Started: {task.objective[:80]}",
                investigation_id=task.parent_investigation_id,
                source="subagent_manager",
                data={
                    "subagent_id": task.subagent_id,
                    "profile": self.profile.value,
                    "name": self.name,
                    "icon": self.icon,
                    "objective": task.objective,
                },
            )
        )

        try:
            result = self._run_investigation(task)
            duration = time.time() - start_time
            result.duration_seconds = duration

            event_bus.publish(
                AgentEvent(
                    type="subagent_settled",
                    status="completed",
                    message=f"[{self.name}] Verdict: {result.verdict.value.upper()}",
                    investigation_id=task.parent_investigation_id,
                    source="subagent_manager",
                    data=result.to_dict(),
                )
            )
            return result

        except Exception as exc:
            duration = time.time() - start_time
            error_result = SubagentStructuredResult(
                subagent_id=task.subagent_id,
                profile=self.profile.value,
                verdict=SubagentVerdict.FAILED,
                confidence=ValidationConfidence.LOW,
                summary=f"Subagent execution encountered an error: {exc}",
                steps_executed=1,
                duration_seconds=duration,
            )
            event_bus.publish(
                AgentEvent(
                    type="subagent_failed",
                    status="error",
                    message=f"[{self.name}] Failed: {exc}",
                    investigation_id=task.parent_investigation_id,
                    source="subagent_manager",
                    data=error_result.to_dict(),
                )
            )
            return error_result

    @abstractmethod
    def _run_investigation(self, task: SubagentTaskRequest) -> SubagentStructuredResult:
        """Concrete subagent execution logic."""
        raise NotImplementedError
