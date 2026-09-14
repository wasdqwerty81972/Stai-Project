"""
CyberOS Core - Policy Engine
Centralized policy management for security actions
"""

import json
import os
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class PolicyRule:
    rule_id: str
    action_type: str
    requires_approval: bool
    minimum_risk: float
    required_role: Optional[str]
    auto_approve_if_risk_below: float
    description: str

    def to_dict(self):
        return {
            'rule_id': self.rule_id,
            'action_type': self.action_type,
            'requires_approval': self.requires_approval,
            'minimum_risk': self.minimum_risk,
            'required_role': self.required_role,
            'auto_approve_if_risk_below': self.auto_approve_if_risk_below,
            'description': self.description,
        }


DEFAULT_POLICIES = [
    {
        'rule_id': 'POL-001',
        'action_type': 'terminate_process',
        'requires_approval': True,
        'minimum_risk': 50.0,
        'required_role': 'administrator',
        'auto_approve_if_risk_below': 25.0,
        'description': 'Terminate a running process. Requires approval for medium+ risk.',
    },
    {
        'rule_id': 'POL-002',
        'action_type': 'quarantine_file',
        'requires_approval': True,
        'minimum_risk': 40.0,
        'required_role': 'administrator',
        'auto_approve_if_risk_below': 20.0,
        'description': 'Quarantine a suspicious file. Requires approval for medium+ risk.',
    },
    {
        'rule_id': 'POL-003',
        'action_type': 'block_ip',
        'requires_approval': True,
        'minimum_risk': 60.0,
        'required_role': 'administrator',
        'auto_approve_if_risk_below': 30.0,
        'description': 'Block a network IP address. Requires approval for high risk.',
    },
    {
        'rule_id': 'POL-004',
        'action_type': 'disable_persistence',
        'requires_approval': True,
        'minimum_risk': 50.0,
        'required_role': 'administrator',
        'auto_approve_if_risk_below': 25.0,
        'description': 'Disable a persistence mechanism. Requires approval for medium+ risk.',
    },
    {
        'rule_id': 'POL-005',
        'action_type': 'disable_account',
        'requires_approval': True,
        'minimum_risk': 70.0,
        'required_role': 'administrator',
        'auto_approve_if_risk_below': 40.0,
        'description': 'Disable a user account. Requires approval for high+ risk.',
    },
    {
        'rule_id': 'POL-006',
        'action_type': 'remove_ssh_key',
        'requires_approval': True,
        'minimum_risk': 60.0,
        'required_role': 'administrator',
        'auto_approve_if_risk_below': 30.0,
        'description': 'Remove an unauthorized SSH key. Requires approval for high risk.',
    },
    {
        'rule_id': 'POL-007',
        'action_type': 'read_processes',
        'requires_approval': False,
        'minimum_risk': 0.0,
        'required_role': None,
        'auto_approve_if_risk_below': 100.0,
        'description': 'Read process list. No approval required.',
    },
    {
        'rule_id': 'POL-008',
        'action_type': 'read_network',
        'requires_approval': False,
        'minimum_risk': 0.0,
        'required_role': None,
        'auto_approve_if_risk_below': 100.0,
        'description': 'Read network connections. No approval required.',
    },
    {
        'rule_id': 'POL-009',
        'action_type': 'scan_system',
        'requires_approval': False,
        'minimum_risk': 0.0,
        'required_role': None,
        'auto_approve_if_risk_below': 100.0,
        'description': 'System scan. No approval required.',
    },
    {
        'rule_id': 'POL-010',
        'action_type': 'investigate',
        'requires_approval': False,
        'minimum_risk': 0.0,
        'required_role': None,
        'auto_approve_if_risk_below': 100.0,
        'description': 'Investigation actions. No approval required.',
    },
]


class PolicyEngine:
    """Centralized policy management for security actions."""

    def __init__(self, storage_path: str = 'cyber_os/policies.json'):
        self.storage_path = storage_path
        self.policies: Dict[str, PolicyRule] = {}
        self._lock = type('threading', (), {'Lock': lambda: type('Lock', (), {'acquire': lambda: None, 'release': lambda: None})()})()
        self._load()

    def _load(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    for rule_id, rule_data in data.items():
                        self.policies[rule_id] = PolicyRule(**rule_data)
            except Exception:
                pass

        if not self.policies:
            for policy_data in DEFAULT_POLICIES:
                rule = PolicyRule(**policy_data)
                self.policies[rule.rule_id] = rule
            self._save()

    def _save(self):
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, 'w') as f:
            json.dump(
                {rule_id: rule.to_dict() for rule_id, rule in self.policies.items()},
                f,
                indent=2,
            )

    def check_policy(self, action_type: str, risk_score: float = 0) -> Dict[str, Any]:
        """Check if an action is permitted and whether approval is required."""
        # Find matching policy
        policy = None
        for rule in self.policies.values():
            if rule.action_type == action_type:
                policy = rule
                break

        if not policy:
            return {
                'allowed': False,
                'requires_approval': True,
                'reason': f'No policy defined for action: {action_type}',
                'policy_id': None,
            }

        # Check minimum risk threshold
        if risk_score < policy.minimum_risk:
            return {
                'allowed': False,
                'requires_approval': True,
                'reason': f'Risk score {risk_score:.1f} below minimum threshold {policy.minimum_risk}',
                'policy_id': policy.rule_id,
            }

        # Determine if approval is required
        requires_approval = policy.requires_approval
        auto_approve = risk_score <= policy.auto_approve_if_risk_below

        return {
            'allowed': True,
            'requires_approval': requires_approval and not auto_approve,
            'auto_approved': auto_approve,
            'policy_id': policy.rule_id,
            'reason': policy.description,
        }

    def gate_action(
        self,
        action_type: str,
        risk_score: float = 0,
        tool_name: str = "",
        arguments: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a structured policy decision for a tool invocation.

        Returns:
            {
                "allowed": bool,
                "requires_approval": bool,
                "auto_approved": bool,
                "policy_id": str | None,
                "reason": str,
                "action_type": str,
                "risk_score": float,
                "tool_name": str,
                "arguments": dict,
                "details": dict,
            }
        """
        decision = self.check_policy(action_type, risk_score)
        return {
            "allowed": decision["allowed"],
            "requires_approval": decision.get("requires_approval", False),
            "auto_approved": decision.get("auto_approved", False),
            "policy_id": decision.get("policy_id"),
            "reason": decision.get("reason", ""),
            "action_type": action_type,
            "risk_score": risk_score,
            "tool_name": tool_name,
            "arguments": arguments or {},
            "details": details or {},
        }

    def add_policy(self, policy: PolicyRule) -> bool:
        """Add or update a policy rule."""
        self.policies[policy.rule_id] = policy
        self._save()
        return True

    def remove_policy(self, rule_id: str) -> bool:
        """Remove a policy rule."""
        if rule_id in self.policies:
            del self.policies[rule_id]
            self._save()
            return True
        return False

    def get_policy(self, action_type: str) -> Optional[PolicyRule]:
        """Get policy for a specific action type."""
        for rule in self.policies.values():
            if rule.action_type == action_type:
                return rule
        return None

    def get_all_policies(self) -> List[PolicyRule]:
        """Get all policy rules."""
        return list(self.policies.values())

    def update_policy(self, rule_id: str, **kwargs) -> bool:
        """Update a policy rule."""
        if rule_id in self.policies:
            rule = self.policies[rule_id]
            for key, value in kwargs.items():
                if hasattr(rule, key):
                    setattr(rule, key, value)
            self._save()
            return True
        return False