import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

@dataclass
class StructuredDecision:
    """The machine-parseable decision contract emitted by the model."""
    action: str  # 'tool' | 'final' | 'ask_user' | 'stop'
    tool: Optional[str] = None
    arguments: Dict[str, Any] = None
    reason_summary: str = ""
    evidence_needed: List[str] = None
    confidence: float = 0.0

    def to_json(self) -> str:
        return json.dumps(self.__dict__)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StructuredDecision':
        return cls(
            action=data.get("action", "stop"),
            tool=data.get("tool"),
            arguments=data.get("arguments", {}),
            reason_summary=data.get("reason_summary", ""),
            evidence_needed=data.get("evidence_needed", []),
            confidence=data.get("confidence", 0.0)
        )
