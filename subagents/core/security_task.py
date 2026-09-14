"""
subagents/core/security_task.py — SVS-Cyber Security Task Specialist

Performs scoped security investigations, vulnerability analysis, and code reviews.
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


class SecurityTaskSubagent(BaseSubagent):
    profile = SubagentProfile.SECURITY_TASK
    name = "Security Task Specialist"
    icon = "🛡️"
    description = "Scoped security task investigation and analysis worker."
    allowed_tools = [
        "static_analysis", "secret_scan", "entropy_check",
        "workspace_read_file", "workspace_list_files", "pty_run"
    ]
    capability_bundles = [
        SubagentCapabilityBundle.CODE_READ,
        SubagentCapabilityBundle.TERMINAL,
        SubagentCapabilityBundle.SYSTEM_INSPECTION,
    ]
    max_steps = 15

    def get_system_prompt(self, task: SubagentTaskRequest) -> str:
        return (
            "You are an SVS-Cyber security task worker. Your objective is to investigate "
            "one concrete security task using authorized tools. Analyze telemetry, inspect artifacts, "
            "and establish proof. Clearly distinguish observations from inferences. "
            "Return a structured security finding with actionable recommendations."
        )

    def _run_investigation(self, task: SubagentTaskRequest) -> SubagentStructuredResult:
        summary = f"Security task completed for objective: {task.objective}"
        findings = []
        verdict = SubagentVerdict.COMPLETED
        confidence = ValidationConfidence.MEDIUM

        if self.agent and hasattr(self.agent, "orchestrator") and hasattr(self.agent.orchestrator, "_call_role"):
            sys_p = self.get_system_prompt(task)
            user_p = self.build_user_prompt(task)
            resp = self.agent.orchestrator._call_role("security_task_worker", sys_p, user_p)
            if resp:
                summary = resp
                if "vulnerability confirmed" in resp.lower() or "critical" in resp.lower() or "high severity" in resp.lower():
                    verdict = SubagentVerdict.CONFIRMED
                    confidence = ValidationConfidence.HIGH
                    findings.append({
                        "id": f"find_{task.subagent_id[:6]}",
                        "title": f"Finding from {self.name}",
                        "severity": "high",
                        "description": summary[:300],
                    })

        return SubagentStructuredResult(
            subagent_id=task.subagent_id,
            profile=self.profile.value,
            verdict=verdict,
            confidence=confidence,
            summary=summary,
            evidence=[task.objective],
            findings=findings,
            steps_executed=1,
        )
