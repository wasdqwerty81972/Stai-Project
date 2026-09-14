"""
subagents/core/validation.py — SVS-Cyber Independent Vulnerability Validator

Independent worker that reproduces or falsifies a single vulnerability candidate.
Never assumes the parent's findings are true; rigorously tests the claim.
"""

from __future__ import annotations

from subagents.base import BaseSubagent
from subagents.contracts import (
    SubagentCapabilityBundle,
    SubagentProfile,
    SubagentStructuredResult,
    SubagentTaskRequest,
    SubagentVerdict,
    ValidationConfidence,
)


class ValidationSubagent(BaseSubagent):
    profile = SubagentProfile.SECURITY_VALIDATION
    name = "Independent Vulnerability Validator"
    icon = "🔬"
    description = "Independent validator that reproduces or falsifies vulnerability candidates."
    allowed_tools = [
        "static_analysis", "secret_scan", "workspace_read_file", "workspace_list_files"
    ]
    capability_bundles = [SubagentCapabilityBundle.CODE_READ, SubagentCapabilityBundle.SYSTEM_INSPECTION]
    max_steps = 15

    def get_system_prompt(self, task: SubagentTaskRequest) -> str:
        return (
            "You are SVS-Cyber's independent vulnerability validation worker. Your ONLY job is "
            "to reproduce or falsify one concrete vulnerability candidate using the minimum necessary scope. "
            "You are completely INDEPENDENT from the parent agent: do not trust its conclusion, do not inherit "
            "its hidden reasoning, and do not rubber-stamp the claim. Treat every parent note as a claim, never as proof. "
            "Require concrete proof of exploitability or flaw. Return CONFIRMED, REJECTED, or INCONCLUSIVE with confidence."
        )

    def _run_investigation(self, task: SubagentTaskRequest) -> SubagentStructuredResult:
        summary = f"Validation completed for candidate: {task.objective}"
        verdict = SubagentVerdict.INCONCLUSIVE
        confidence = ValidationConfidence.UNCONFIRMED
        evidence = []
        findings = []

        if self.agent and hasattr(self.agent, "orchestrator") and hasattr(self.agent.orchestrator, "_call_role"):
            sys_p = self.get_system_prompt(task)
            user_p = self.build_user_prompt(task)
            resp = self.agent.orchestrator._call_role("independent_validator", sys_p, user_p)
            if resp:
                summary = resp
                lower = resp.lower()
                if "confirmed" in lower or "reproduced" in lower or "valid vulnerability" in lower:
                    verdict = SubagentVerdict.CONFIRMED
                    confidence = ValidationConfidence.HIGH
                    evidence.append("Reproduced with concrete evidence")
                elif "rejected" in lower or "falsified" in lower or "not vulnerable" in lower or "false positive" in lower:
                    verdict = SubagentVerdict.REJECTED
                    confidence = ValidationConfidence.HIGH
                    evidence.append("Falsified candidate / proven false positive")
                else:
                    verdict = SubagentVerdict.INCONCLUSIVE
                    confidence = ValidationConfidence.LOW

        return SubagentStructuredResult(
            subagent_id=task.subagent_id,
            profile=self.profile.value,
            verdict=verdict,
            confidence=confidence,
            summary=summary,
            evidence=evidence,
            findings=findings,
            steps_executed=1,
        )
