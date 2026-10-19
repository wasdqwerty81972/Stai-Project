from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid

class EvidenceType(Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    HYPOTHESIS = "hypothesis"
    UNKNOWN = "unknown"

class Evidence:
    def __init__(self, 
                 content: Any, 
                 type: EvidenceType = EvidenceType.OBSERVED, 
                 source: Optional[str] = None,
                 metadata: Optional[Dict[str, Any]] = None):
        self.id = str(uuid.uuid4())[:8]
        self.content = content
        self.type = type
        self.source = source
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "content": self.content,
            "source": self.source,
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }

class EvidenceManager:
    """Manages the collection, normalization, and compaction of investigation evidence."""

    def __init__(self):
        self.evidence_list: List[Evidence] = []

    def add_evidence(self, 
                     content: Any, 
                     type: EvidenceType = EvidenceType.OBSERVED, 
                     source: Optional[str] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> Evidence:
        ev = Evidence(content, type, source, metadata)
        self.evidence_list.append(ev)
        return ev

    def get_all_evidence(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.evidence_list]

    def compact_for_context(self, max_items: int = 10) -> List[Dict[str, Any]]:
        """Normalizes and limits evidence for model context to avoid token exhaustion."""
        # Simple recent-first compaction for now
        sorted_ev = sorted(self.evidence_list, key=lambda x: x.timestamp, reverse=True)
        return [e.to_dict() for e in sorted_ev[:max_items]]

    def clear(self):
        self.evidence_list = []
