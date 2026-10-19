"""
subagents — SVS-Cyber Autonomous Subagent Framework

Contains:
- subagents/ts/        -> TypeScript subagent engines
- subagents/ui/        -> React/TSX subagent drawer and card components
- subagents/core/      -> Core autonomous task workers (General, Security Task, Validation)
- subagents/cyber/     -> Defensive specialist subagents (Threat Intel, Malware, Incident, etc.)
- subagents/contracts  -> Unified data contracts, verdicts, and tasks
- subagents/manager    -> Central orchestrator for subagent dispatch and settlement
"""

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
from subagents.base import BaseSubagent
from subagents.registry import SUBAGENT_REGISTRY, get_subagent_class, list_all_subagents
from subagents.manager import UnifiedSubagentManager

__all__ = [
    "SubagentCapabilityBundle",
    "SubagentContextRef",
    "SubagentProfile",
    "SubagentStatus",
    "SubagentStructuredResult",
    "SubagentTaskRequest",
    "SubagentVerdict",
    "ValidationConfidence",
    "BaseSubagent",
    "SUBAGENT_REGISTRY",
    "get_subagent_class",
    "list_all_subagents",
    "UnifiedSubagentManager",
]
