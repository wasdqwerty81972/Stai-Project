"""
subagents/manager.py — Unified Subagent Orchestrator & Lifecycle Manager

Orchestrates all subagents (core task workers + SVS-Cyber defensive specialists):
- Threadpool execution with scoped execution budgets
- Lifecycle settlement and parent ledger reporting
- Live WebSocket and UI event streaming
"""

from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from subagents.contracts import (
    SubagentContextRef,
    SubagentProfile,
    SubagentStatus,
    SubagentStructuredResult,
    SubagentTaskRequest,
    SubagentVerdict,
    ValidationConfidence,
)
from subagents.registry import get_subagent_class, list_all_subagents
from ui.event_bus import AgentEvent, event_bus


class UnifiedSubagentManager:
    """Central lifecycle orchestrator for all subagents in SVS-Cyber."""

    def __init__(self, agent: Any = None) -> None:
        self.agent = agent
        self._lock = threading.Lock()
        self.active_tasks: Dict[str, SubagentTaskRequest] = {}
        self.settled_results: Dict[str, SubagentStructuredResult] = {}

    def delegate_task(
        self,
        profile_name: str,
        objective: str,
        parent_investigation_id: str = "",
        context_refs: Optional[List[Dict[str, str]]] = None,
        success_criteria: Optional[List[str]] = None,
    ) -> SubagentStructuredResult:
        """Spawns and executes any subagent, returning a structured settlement verdict."""
        subagent_cls = get_subagent_class(profile_name)
        subagent_instance = subagent_cls(agent=self.agent)

        subagent_id = f"sub_{uuid.uuid4().hex[:8]}"
        parsed_refs = [
            SubagentContextRef(label=r.get("label", "Ref"), content=r.get("content", ""))
            for r in (context_refs or [])
        ]

        task = SubagentTaskRequest(
            subagent_id=subagent_id,
            parent_investigation_id=parent_investigation_id,
            profile=subagent_cls.profile,
            objective=objective,
            success_criteria=success_criteria or ["Analyze evidence and produce structured findings."],
            capability_bundles=subagent_cls.capability_bundles,
            context_refs=parsed_refs,
            max_steps=subagent_cls.max_steps,
        )

        with self._lock:
            self.active_tasks[subagent_id] = task

        # Execute
        result = subagent_instance.execute(task)

        with self._lock:
            self.active_tasks.pop(subagent_id, None)
            self.settled_results[subagent_id] = result

        return result

    def list_available_subagents(self) -> List[Dict[str, Any]]:
        return list_all_subagents()

    def get_result(self, subagent_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            res = self.settled_results.get(subagent_id)
            return res.to_dict() if res else None
