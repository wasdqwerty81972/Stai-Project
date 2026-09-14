from typing import Dict, Any, Optional
import time
from .structured_decision import StructuredDecision, parse_model_decision
from .context_builder import ContextBuilder
from .evidence_manager import EvidenceManager

class AgentLoop:
    """The core agent orchestration loop."""

    def __init__(self, agent_instance: Any, context_builder: ContextBuilder, evidence_manager: EvidenceManager):
        self.agent = agent_instance
        self.context_builder = context_builder
        self.evidence_manager = evidence_manager
        self.max_iterations = 20
        self.iteration = 0

    def run(self, objective: str, initial_context: Dict[str, Any]) -> Dict[str, Any]:
        """Executes the agent loop until the objective is satisfied or limits reached."""
        
        while self.iteration < self.max_iterations:
            self.iteration += 1
            
            # 1. Construct Context
            context = self.context_builder.build(
                objective,
                initial_context, # Needs to be updated dynamically
                self.agent.guardrails.__dict__,
                list(self.agent.registry.tools.keys())
            )
            
            # 2. Invoke Model (using existing SVS AI provider wrapper)
            model_output = self.agent.orchestrator.coordinate_incident_response(context)
            
            # 3. Parse Decision
            decision = parse_model_decision(model_output)
            if not decision:
                return {"status": "failed", "reason": "Model decision parsing failed"}
            
            # 4. Handle Actions
            if decision.action == "final":
                return {"status": "completed", "final_answer": decision.reason_summary}
            
            elif decision.action == "tool":
                result = self.agent.execute_tool(decision.tool, decision.arguments)
                # Normalize result and update evidence
                self.evidence_manager.add_evidence(result, source=decision.tool)
                initial_context["findings"] = self.evidence_manager.get_all_evidence()
            
            elif decision.action == "stop":
                return {"status": "stopped", "reason": decision.reason_summary}
                
            # Loop continues...
            
        return {"status": "halt", "reason": "Iteration limit reached"}
