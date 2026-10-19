"""ToolResult - Unified tool response wrapper for standardized evidence aggregation."""

import time
from typing import Dict, Any, List, Optional


class ToolResult:
    """
    Unified result wrapper for all tool execution.
    Ensures consistent structure for evidence aggregation and model reasoning.
    """
    def __init__(
        self,
        tool_name: str,
        success: bool,
        findings: Optional[List[Dict[str, Any]]] = None,
        raw_output: str = "",
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
    ):
        self.tool_name = tool_name
        self.success = success
        self.findings = findings or []
        self.raw_output = raw_output
        self.error = error
        self.metadata = metadata or {}
        self.evidence = evidence or []
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for JSON serialization."""
        return {
            "tool": self.tool_name,
            "success": self.success,
            "findings": self.findings,
            "findings_count": len(self.findings),
            "raw_output": self.raw_output,
            "error": self.error,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "evidence": self.evidence,
        }

    def add_evidence(self, evidence_item: Dict[str, Any]) -> None:
        """Append an evidence artifact to this result."""
        self.evidence.append(evidence_item)

    @staticmethod
    def success_with_findings(
        tool_name: str,
        findings: Optional[List[Dict[str, Any]]] = None,
        raw_output: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
    ) -> "ToolResult":
        """Helper for successful tool execution with findings."""
        return ToolResult(
            tool_name=tool_name,
            success=True,
            findings=findings or [],
            raw_output=raw_output,
            error=None,
            metadata=metadata,
            evidence=evidence or [],
        )

    @staticmethod
    def failure(tool_name: str, error: str, metadata: Optional[Dict[str, Any]] = None) -> "ToolResult":
        """Helper for tool execution failure."""
        return ToolResult(
            tool_name=tool_name,
            success=False,
            findings=[],
            raw_output="",
            error=error,
            metadata=metadata or {},
         )
