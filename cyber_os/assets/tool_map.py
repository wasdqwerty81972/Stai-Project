"""
cyber_os/assets/tool_map.py — Claude-style tool names to SVS tool names.

Markdown subagent definitions declare their tool access in Claude Code's
vocabulary (``tools: Read, Grep, Glob, Bash``). SVS's ``ToolRegistry`` uses its
own names. This module translates between them.

Only mappings whose SVS target is known to be registered are listed. A Claude
tool with no SVS equivalent is reported through
:func:`translate`'s ``unmapped`` list instead of being guessed at — a wrong
mapping would silently hand a subagent the wrong capability, and a dropped one
would silently remove a capability its system prompt still assumes it has.

SVS's existing hand-written allowlists in ``cyber_os/subagents/profiles.py``
name four tools that are not in the registry (``file_analyze``,
``list_findings``, ``read_processes``, ``run_terminal_cmd``), which is why
:func:`filter_to_registered` exists: definitions loaded from markdown are
validated against the live registry so they cannot repeat that.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple

# Claude Code tool name -> SVS ToolRegistry tool name.
#
# Read/Glob map onto the workspace pair, which is path-confined by
# ``_safe_workspace_path``. Bash maps onto ``shell_exec``, which stays behind
# the guardrail layer at its registered risk level.
CLAUDE_TO_SVS: Dict[str, str] = {
    "Read": "workspace_read_file",
    "Glob": "workspace_list_files",
    "Bash": "shell_exec",
    "WebSearch": "web_search",
}

# Claude tools with no SVS equivalent. Listed explicitly so `translate` can tell
# "this project has no such capability" apart from "nobody has looked at this
# name yet", which matters when a definition's prompt depends on it.
KNOWN_UNSUPPORTED: Dict[str, str] = {
    "Write": "SVS exposes no general-purpose workspace write tool",
    "Edit": "SVS exposes no general-purpose workspace edit tool",
    "Grep": "SVS exposes no general-purpose content search tool",
    "WebFetch": "SVS web tools are analysis-specific, not general fetch",
}


def translate(
    claude_tools: Iterable[str],
) -> Tuple[List[str], List[str]]:
    """Map Claude tool names to SVS names.

    Returns ``(svs_tools, unmapped)``. ``unmapped`` keeps the original Claude
    names, including ``mcp__*`` entries, which SVS has no transport for.
    """
    svs_tools: List[str] = []
    unmapped: List[str] = []

    for name in claude_tools:
        target = CLAUDE_TO_SVS.get(name)
        if target is None:
            unmapped.append(name)
            continue
        if target not in svs_tools:
            svs_tools.append(target)

    return svs_tools, unmapped


def filter_to_registered(
    tools: Sequence[str],
    registered: Iterable[str],
) -> Tuple[List[str], List[str]]:
    """Split ``tools`` into those present in ``registered`` and those absent."""
    available = set(registered)
    present = [name for name in tools if name in available]
    missing = [name for name in tools if name not in available]
    return present, missing


def explain_unmapped(name: str) -> str:
    """Return why a Claude tool name has no SVS target."""
    if name in KNOWN_UNSUPPORTED:
        return KNOWN_UNSUPPORTED[name]
    if name.startswith("mcp__"):
        return "MCP tool; SVS has no MCP transport"
    return "no SVS equivalent is defined"
