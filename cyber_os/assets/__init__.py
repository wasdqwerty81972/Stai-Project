"""
cyber_os/assets — SVS-Cyber canonical asset registries.

Wires the four project-root asset directories into the SVS runtime:

* ``commands/``            -> :mod:`cyber_os.assets.commands`
* ``skills/``              -> :mod:`cyber_os.assets.skills`
* ``subagents/definitions/`` -> :mod:`cyber_os.assets.agents`
* ``cyber_tools/``         -> scanned by ``cyber_tools.register_dynamic_cyber_tools``

These directories are canonical. Assets were copied out of the read-only
``ECC-source/`` and ``HackerAI-Source/`` checkouts; nothing here resolves back
into them.

Each registry is exposed as a process-wide singleton so the desktop workspace,
the FastAPI server, and the agent itself all observe one view of what exists.
"""

from __future__ import annotations

from cyber_os.assets.agents import (
    AgentDefinition,
    AgentDefinitionRegistry,
    get_agent_definition_registry,
)
from cyber_os.assets.commands import (
    CommandDefinition,
    CommandRegistry,
    ExpandedCommand,
    get_command_registry,
)
from cyber_os.assets.skills import (
    SkillDefinition,
    SkillRegistry,
    get_skill_registry,
)

__all__ = [
    "AgentDefinition",
    "AgentDefinitionRegistry",
    "CommandDefinition",
    "CommandRegistry",
    "ExpandedCommand",
    "SkillDefinition",
    "SkillRegistry",
    "get_agent_definition_registry",
    "get_command_registry",
    "get_skill_registry",
]
