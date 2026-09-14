"""Optional NeMo Agent Toolkit compatibility for CyberAgent.

The native PySide6 console remains the UI. This adapter lets the backend expose
its tools and workflow metadata to NAT when ``nvidia-nat`` is installed without
making NAT, NVIDIA NIM, or an NVIDIA API key a runtime requirement.
"""

from __future__ import annotations

import importlib.util
from typing import Any, Dict, Iterable, List

from ui.event_bus import AgentEvent, event_bus


class NeMoAgentToolkitBridge:
    """Translate CyberAgent capabilities into NAT-friendly metadata."""

    def __init__(self, tool_manifest: Iterable[Dict[str, Any]], workspace: str) -> None:
        self._tools = list(tool_manifest)
        self.workspace = workspace
        self.available = importlib.util.find_spec("nat") is not None

    def status(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "package": "nvidia-nat",
            "native_ui": "PySide6",
            "workspace": self.workspace,
            "tool_count": len(self._tools),
            "features": ["composable tools", "workflow metadata", "observability hook"],
        }

    def functions_config(self) -> List[Dict[str, Any]]:
        """Return tool metadata suitable for generating a NAT workflow config."""
        return [
            {
                "name": tool["name"],
                "description": tool.get("description", tool["name"]),
                "metadata": {
                    "risk_level": tool.get("risk_level", "read_only"),
                    "requires_admin": tool.get("requires_admin", False),
                    "environments": tool.get("environments", []),
                },
            }
            for tool in self._tools
        ]

    def workflow_config(self, workflow_name: str = "cyberagent-investigation") -> Dict[str, Any]:
        """Build a declarative NAT-style workflow description for inspection/export."""
        return {
            "workflow": {
                "_type": "react_agent",
                "name": workflow_name,
                "tool_names": [tool["name"] for tool in self._tools],
                "description": "CyberAgent defensive investigation workflow",
            },
            "security": {
                "allowlist_enforced": True,
                "destructive_actions_require_approval": True,
                "native_ui": "PySide6",
            },
        }

    def publish_intermediate_step(self, step: Any, investigation_id: str = "") -> AgentEvent:
        """Translate a NAT IntermediateStep-like object into a UI event.

        Duck typing keeps the native app compatible with multiple NAT releases;
        the bridge does not require NAT to be installed for local execution.
        """
        name = getattr(step, "name", None) or getattr(step, "function_name", None) or "Agent step"
        status = str(getattr(step, "status", "running")).lower()
        if status in {"success", "completed", "finished"}:
            event_type = "nat_step_completed"
            status = "completed"
        elif status in {"error", "failed", "failure"}:
            event_type = "nat_step_failed"
            status = "error"
        else:
            event_type = "nat_step_started"
            status = "running"
        data = {
            "step_id": str(getattr(step, "step_id", getattr(step, "id", ""))),
            "parent_id": str(getattr(step, "parent_id", "")),
            "step_type": str(getattr(step, "step_type", getattr(step, "type", ""))),
            "input": getattr(step, "input", None),
            "output": getattr(step, "output", None),
        }
        event = AgentEvent(
            type=event_type,
            investigation_id=investigation_id,
            source="nemo_agent_toolkit",
            status=status,
            message=str(name),
            data=data,
        )
        event_bus.publish(event)
        return event

    def publish_orchestration_step(self, step: Any, investigation_id: str = "") -> AgentEvent:
        """Publish a local orchestrator step using the same NAT UI event contract."""
        status = str(getattr(step, "status", "running")).lower()
        if status in {"completed", "success", "finished"}:
            status = "completed"
        elif status in {"failed", "error", "failure"}:
            status = "error"
        else:
            status = "running"

        data = {
            "phase": getattr(step, "phase", ""),
            "tool": getattr(step, "tool", None),
            "input_summary": getattr(step, "input_summary", ""),
            "output_summary": getattr(step, "output_summary", ""),
            "duration_ms": getattr(step, "duration_ms", None),
        }
        event = AgentEvent(
            type="nat_step_completed" if status == "completed" else "nat_step_failed" if status == "error" else "nat_step_started",
            investigation_id=investigation_id,
            source="nemo_agent_toolkit",
            status=status,
            message=str(getattr(step, "phase", "Agent step")).replace("_", " ").title(),
            data=data,
        )
        event_bus.publish(event)
        return event
