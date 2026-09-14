"""
CyberAgent Core - Context Builder
Assembles layered context for the AI model to drive evidence-based investigations.
"""

from typing import Any, Dict, List, Optional
import json
from datetime import datetime

class ContextBuilder:
    def __init__(self, agent_name: str, objective: str):
        self.agent_name = agent_name
        self.objective = objective
        self.version = "1.0"
        
        # Bounded limits (defaults)
        self.MAX_EVENTS = 15
        self.MAX_EVIDENCE = 20
        self.MAX_FINDINGS = 10
        self.MAX_HYPOTHESES = 5
        self.MAX_TOOL_HISTORY = 10
        self.MAX_CONVERSATION = 5
        self.MAX_TOOLS = 20
        self.MAX_CONTEXT_CHARS = 10000

    def build_identity_context(self) -> str:
        return (
            "Identity: You are SVS-Cyber, a defensive cybersecurity investigation agent.\n"
            "Methodology: Evidence-first, hypothesis-driven, bounded loop investigation.\n"
            "Rules: Only OBSERVED (tool data) is fact. INFERRED and HYPOTHESIS are not fact.\n"
            "Constraint: Never fabricate evidence. Policy engine is authoritative." 
        )

    def build_mission_context(self, user_request: str, scope: Optional[str] = "UNKNOWN", target: Optional[str] = "UNKNOWN") -> str:
        return (
            f"Mission: {self.objective}\n"
            f"Current Request: {user_request}\n"
            f"Authorized Scope: {scope}\n"
            f"Target: {target}\n"
            "Desired Outcome: Determine cause and recommend remediation (if applicable, otherwise UNKNOWN)."
        )

    def build_investigation_state_context(self, state: Dict[str, Any]) -> str:
        events = state.get("events", [])[-self.MAX_EVENTS:]
        findings = state.get("findings", [])[-self.MAX_FINDINGS:]
        return (
            f"Investigation State: Status={state.get('status', 'running')}, Iteration={state.get('iteration_count', 0)}\n"
            f"Recent Events: {json.dumps(events)}\n"
            f"Findings: {json.dumps(findings)}"
        )

    def build_environment_context(self, env_data: Dict[str, Any]) -> str:
        return (
            f"Environment: OS={env_data.get('os', 'UNKNOWN')}, Type={env_data.get('type', 'UNKNOWN')}\n"
            f"Capabilities: Terminal={env_data.get('has_terminal', False)}, Browser={env_data.get('has_browser', False)}"
        )

    def build_evidence_context(self, evidence: List[Dict[str, Any]]) -> str:
        lines = ["Evidence:"]
        for item in evidence[-self.MAX_EVIDENCE:]:
            lines.append(f"- [E{item.get('evidence_id', 'UNKNOWN')}] Type: {item.get('type', 'UNKNOWN')}, Source: {item.get('source', 'UNKNOWN')}, Summary: {item.get('summary', 'UNKNOWN')}")
        return "\n".join(lines)

    def build_hypothesis_context(self, hypotheses: List[Dict[str, Any]]) -> str:
        lines = ["Hypotheses:"]
        for h in hypotheses[-self.MAX_HYPOTHESES:]:
            lines.append(f"- Hypothesis: {h.get('hypothesis', 'UNKNOWN')} (Status: {h.get('status', 'untested')}, Confidence: {h.get('confidence', 0.0):.2f})")
        return "\n".join(lines)

    def build_tool_context(self, tools: List[Dict[str, Any]]) -> str:
        lines = ["Available Tools:"]
        for t in tools:
            # Defensive access to tool metadata
            name = t.get('name', 'UNKNOWN_TOOL')
            description = t.get('description', 'No description available.')
            risk_level = t.get('risk_level', 'unknown')
            read_only = t.get('read_only', False)
            requires_approval = t.get('requires_approval', False)

            lines.append(f"- Name: {name}\n  Description: {description}\n  Risk: {risk_level}, ReadOnly: {read_only}, Approval: {requires_approval}")
        return "\n".join(lines)

    def build_policy_context(self, policy_state: Dict[str, Any]) -> str:
        return (
            "Policy & Authorization:\n"
            f"Authorization Status: {policy_state.get('authorization_status', 'UNKNOWN')}\n"
            f"Allowed Actions: {json.dumps(policy_state.get('allowed_actions', []))}\n"
            f"Restricted Actions: {json.dumps(policy_state.get('restricted_actions', []))}\n"
            f"Approval Pending: {policy_state.get('pending_approvals', False)}"
        )

    def build_conversation_context(self, conversation_history: List[Dict[str, Any]]) -> str:
        # Bounded conversation history
        lines = ["Conversation History:"]
        for msg in conversation_history[-self.MAX_CONVERSATION:]:
            lines.append(f"- {msg.get('speaker', 'UNKNOWN')}: {msg.get('text', 'UNKNOWN')}")
        return "\n".join(lines)

    def build_decision_contract(self) -> str:
        return (
            "Output Format (JSON only):\n"
            '{"action": "tool | final | ask_user | stop", "tool": "string | null", "arguments": {}, ' 
            '"reason_summary": "concise explanation", "evidence_needed": [], "confidence": float}\n' 
            "For 'final': {'action': 'final', 'final': '...', 'findings': [], 'confidence': float}\n" 
            "For 'ask_user': {'action': 'ask_user', 'question': '...'}\n" 
            "For 'stop': {'action': 'stop', 'reason': '...'}"
        )

    def build_prompt(self, 
                     state: Dict[str, Any], 
                     relevant_tools: List[Dict[str, Any]], 
                     policy_state: Dict[str, Any],
                     user_request: str, 
                     conversation_history: List[Dict[str, Any]],
                     env_data: Dict[str, Any],
                     hypotheses: List[Dict[str, Any]]) -> str:
        
        # Build sections separately
        identity_sec = self.build_identity_context()
        mission_sec = self.build_mission_context(user_request)
        investigation_state_sec = self.build_investigation_state_context(state)
        environment_sec = self.build_environment_context(env_data)
        evidence_sec = self.build_evidence_context(state.get("evidence", []))
        hypotheses_sec = self.build_hypothesis_context(hypotheses)
        tool_sec = self.build_tool_context(relevant_tools)
        policy_sec = self.build_policy_context(policy_state)
        conversation_sec = self.build_conversation_context(conversation_history)
        decision_contract_sec = self.build_decision_contract()

        # Prioritize sections to fit within budget, always preserving core instructions
        # This is a basic char-based approach; token-aware would be better if available.
        sections_to_include = [
            identity_sec,
            decision_contract_sec,
            mission_sec,
            policy_sec,
            environment_sec,
            investigation_state_sec,
            hypotheses_sec,
            evidence_sec,
            tool_sec,
            conversation_sec,
        ]
        
        final_prompt_parts = []
        current_chars = 0
        
        for section in sections_to_include:
            if current_chars + len(section) + len("\n\n") <= self.MAX_CONTEXT_CHARS:
                final_prompt_parts.append(section)
                current_chars += len(section) + len("\n\n")
            else:
                # If a section doesn't fit, try to truncate dynamic parts if it's not identity/contract
                # This is a simplified truncation for now; more granular control would be in a real token-aware system.
                if section is conversation_sec:
                    truncated_conv = self.build_conversation_context(conversation_history[-1:]) # Last message only
                    if current_chars + len(truncated_conv) + len("\n\n") <= self.MAX_CONTEXT_CHARS:
                        final_prompt_parts.append(truncated_conv)
                break # Stop adding sections if budget is exhausted
                
        return "\n\n".join(final_prompt_parts)

    def get_context_metadata(self, state: Dict[str, Any], relevant_tools: List[Dict[str, Any]], 
                             policy_state: Dict[str, Any], user_request: str, 
                             conversation_history: List[Dict[str, Any]],
                             env_data: Dict[str, Any],
                             hypotheses: List[Dict[str, Any]]) -> Dict[str, Any]:
        # Re-run build without truncation to get full size for metadata. This is inefficient.
        full_prompt = self.build_prompt(state, relevant_tools, policy_state, user_request, conversation_history, env_data, hypotheses)
        
        return {
            