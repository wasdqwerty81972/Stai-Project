"""CyberOS - Autonomous Cyber Defense System.

Public names remain available from ``cyber_os`` while their implementation
modules load only when a caller asks for them. This keeps focused entry points
such as the Windows protection service from initializing the whole agent UI.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any


_EXPORT_MODULES = {
    "CyberOSEngine": ".engine",
    "EventMonitor": ".engine",
    "NetworkMonitor": ".engine",
    "ProcessMonitor": ".engine",
    "FileSystemMonitor": ".engine",
    "PowerShellMonitor": ".engine",
    "SecurityEvent": ".engine",
    "ThreatAlert": ".engine",
    "Severity": ".engine",
    "CyberOSAI": ".cyber_os_ai",
    "launch_attack": ".cyber_os_attacks",
    "restore_test_files": ".cyber_os_attacks",
    "IncidentManager": ".incident_manager",
    "Finding": ".incident_manager",
    "Incident": ".incident_manager",
    "CorrelationEngine": ".correlation_engine",
    "MitreEngine": ".mitre_engine",
    "AttackTechnique": ".mitre_engine",
    "AttackChain": ".mitre_engine",
    "PolicyEngine": ".policy_engine",
    "ResponseEngine": ".response_engine",
    "ResponseResult": ".response_engine",
    "SOCDashboard": ".cyber_os_soc",
    "launch_soc_dashboard": ".cyber_os_soc",
    "AgentEventBus": ".agent_bus",
    "Session": ".agent_bus",
    "SessionManager": ".agent_bus",
    "EventType": ".agent_bus",
    "AgentEvent": ".agent_bus",
    "IntentRouter": ".intent_router",
    "IntentType": ".intent_router",
    "IntentResult": ".intent_router",
}

_OPTIONAL_WORKSPACE_EXPORTS = {"AgentWorkspace", "launch_workspace"}

__all__ = [
    "CyberOSEngine",
    "CyberOSAI",
    "IncidentManager",
    "Finding",
    "Incident",
    "CorrelationEngine",
    "MitreEngine",
    "AttackTechnique",
    "AttackChain",
    "PolicyEngine",
    "ResponseEngine",
    "ResponseResult",
    "SOCDashboard",
    "launch_soc_dashboard",
    "AgentWorkspace",
    "launch_workspace",
    "AgentEventBus",
    "Session",
    "SessionManager",
    "EventType",
    "AgentEvent",
    "IntentRouter",
    "IntentType",
    "IntentResult",
    "launch_attack",
    "restore_test_files",
    "EventMonitor",
    "NetworkMonitor",
    "ProcessMonitor",
    "FileSystemMonitor",
    "PowerShellMonitor",
    "SecurityEvent",
    "ThreatAlert",
    "Severity",
]


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is not None:
        value = getattr(import_module(module_name, __name__), name)
        globals()[name] = value
        return value

    if name in _OPTIONAL_WORKSPACE_EXPORTS:
        try:
            module = import_module(".workspace", __name__)
        except ImportError:
            globals().update(AgentWorkspace=None, launch_workspace=None)
            return None
        for export_name in _OPTIONAL_WORKSPACE_EXPORTS:
            globals()[export_name] = getattr(module, export_name)
        return globals()[name]

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
