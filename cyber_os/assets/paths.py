"""
cyber_os/assets/paths.py — Canonical asset directory resolution.

The four asset directories (``commands/``, ``subagents/definitions/``,
``cyber_tools/``, ``skills/``) live at the project root. They are the canonical
locations: nothing here resolves back into ``ECC-source/`` or
``HackerAI-Source/``, which are read-only reference checkouts.

Paths are derived from this file's location so the project stays relocatable.
``SVS_PROJECT_ROOT`` overrides the root for tests and packaged deployments.
"""

from __future__ import annotations

import os
from pathlib import Path

# cyber_os/assets/paths.py -> cyber_os/assets -> cyber_os -> <project root>
_DERIVED_ROOT = Path(__file__).resolve().parents[2]


def project_root() -> Path:
    """Return the project root, honouring the ``SVS_PROJECT_ROOT`` override."""
    override = os.environ.get("SVS_PROJECT_ROOT", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return _DERIVED_ROOT


def commands_dir() -> Path:
    """Directory holding markdown command definitions."""
    return project_root() / "commands"


def skills_dir() -> Path:
    """Directory holding skill bundles, one subdirectory per skill."""
    return project_root() / "skills"


def agent_definitions_dir() -> Path:
    """Directory holding markdown subagent definitions."""
    return project_root() / "subagents" / "definitions"


def cyber_tools_dir() -> Path:
    """Directory scanned for ``CyberToolPlugin`` drop-in tools."""
    return project_root() / "cyber_tools"
