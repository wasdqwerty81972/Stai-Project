from typing import Dict, Any, List
from datetime import datetime, timezone
import json

class ContextBuilder:
    """Assembles model-facing context based on investigation state, policy, and task scope."""

    def __init__(self, system_identity: str):
        self.system_identity = system_identity

    def build(self, 
              objective: str, 
              investigation_state: Dict[str, Any],
              policy_state: Dict[str, Any],
              available_tools: List[Dict[str, Any]]) -> str:
        
        context_parts = []
        context_parts.append(f"<system>\n{self.system_identity}\n</system>")
        context_parts.append(f"<task>\nObjective: {objective}\n</task>")
        
        # Assemble investigation state findings/history
        findings = investigation_state.get("findings", [])
        if findings:
            context_parts.append(f"<findings>\n{json.dumps(findings, indent=2)}\n</findings>")
            
        # Assemble policy / approval state
        context_parts.append(f"<policy>\n{json.dumps(policy_state, indent=2)}\n</policy>")
        
        # Assemble relevant tools (filtering/relevance could be added here)
        context_parts.append(f"<available_tools>\n{json.dumps(available_tools, indent=2)}\n</available_tools>")
        
        # Add timestamp
        context_parts.append(f"<timestamp>{datetime.now(timezone.utc).isoformat()}</timestamp>")
        
        return "\n\n".join(context_parts)
