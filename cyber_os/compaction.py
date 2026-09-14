"""
cyber_os/compaction.py — Context Management & Tool Output Pruning for SVS-Cyber

Implements rolling token budget management, tool output pruning, and retained-tail
compaction to prevent context overflow while preserving essential investigation state.

Adapted from mature agent compaction architecture for SVS-Cyber.

Rules:
1. Tool outputs newer than the protection budget are kept intact.
2. Older, non-protected tool outputs are replaced with concise one-line markers:
   `[Terminal: ran '<command>' (exit: 0, <N> lines)]`
   `[File: read '<path>' (<N> bytes)]`
   `[Tool: <name> completed (<N> bytes)]`
3. Protected tools (task management, notes, findings) are NEVER pruned.
4. Provides rolling context summarization with a retained tail of recent messages.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

# Token budget defaults (approximate 4 chars per token)
DEFAULT_TOOL_OUTPUT_TOKEN_BUDGET = 25_000
CHARS_PER_TOKEN = 4

# Tools whose outputs must NEVER be pruned because they represent ongoing state
PROTECTED_TOOLS: Set[str] = {
    "todo_write",
    "notes",
    "create_note",
    "list_notes",
    "update_note",
    "delete_note",
    "finding_created",
    "evidence_added",
}


def estimate_tokens(text: str) -> int:
    """Estimates token count from text length."""
    if not text:
        return 0
    return max(1, len(text) // CHARS_PER_TOKEN)


def format_pruned_placeholder(tool_name: str, args: Dict[str, Any], output_str: str) -> str:
    """Builds a compact summary placeholder for an older tool output."""
    line_count = len(output_str.splitlines()) if output_str else 0
    byte_count = len(output_str.encode("utf-8")) if output_str else 0

    if tool_name in ("run_terminal_cmd", "interact_terminal_session", "shell_exec"):
        cmd = args.get("command") or args.get("cmd") or "terminal command"
        short_cmd = (cmd[:60] + "...") if len(cmd) > 60 else cmd
        return f"[Terminal: ran '{short_cmd}' ({line_count} lines, {byte_count} bytes) - output compacted]"
    elif tool_name in ("workspace_read_file", "file_read", "read_file"):
        path = args.get("filepath") or args.get("path") or "file"
        return f"[File: read '{path}' ({byte_count} bytes) - output compacted]"
    elif tool_name in ("workspace_list_files", "list_files"):
        return f"[File Listing: {line_count} files discovered - output compacted]"
    elif tool_name == "windows_defender_scan":
        target = args.get("path") or args.get("target") or "target"
        return f"[Defender Scan: completed for '{target}' ({line_count} lines) - output compacted]"
    else:
        return f"[Tool '{tool_name}': completed ({byte_count} bytes) - output compacted]"


@dataclass
class PruneResult:
    steps: List[Dict[str, Any]]
    pruned_count: int
    tokens_saved: int
    total_tokens: int


class ContextCompactor:
    """Manages tool output pruning and message history compaction."""

    def __init__(
        self,
        tool_output_token_budget: int = DEFAULT_TOOL_OUTPUT_TOKEN_BUDGET,
        messages_to_keep_unsummarized: int = 6,
    ) -> None:
        self.tool_output_token_budget = tool_output_token_budget
        self.messages_to_keep_unsummarized = messages_to_keep_unsummarized

    def prune_tool_steps(self, steps: List[Dict[str, Any]]) -> PruneResult:
        """
        Iterates backwards from newest to oldest steps.
        Retains full output until budget is exceeded; compacts older non-protected outputs.
        """
        accumulated_tokens = 0
        pruned_count = 0
        tokens_saved = 0
        processed_steps: List[Dict[str, Any]] = []

        # Process in reverse (newest first)
        for step in reversed(steps):
            step_copy = dict(step)
            tool_name = step_copy.get("tool") or ""
            raw_output = step_copy.get("output", "")
            if not isinstance(raw_output, str):
                raw_output = json.dumps(raw_output, default=str)

            output_tokens = estimate_tokens(raw_output)

            # Protected tools are never pruned
            if tool_name in PROTECTED_TOOLS:
                accumulated_tokens += output_tokens
                processed_steps.append(step_copy)
                continue

            # If within budget, keep intact
            if (accumulated_tokens + output_tokens) <= self.tool_output_token_budget:
                accumulated_tokens += output_tokens
                processed_steps.append(step_copy)
            else:
                # Exceeds budget: compact older output
                placeholder = format_pruned_placeholder(
                    tool_name,
                    step_copy.get("arguments") or {},
                    raw_output,
                )
                placeholder_tokens = estimate_tokens(placeholder)
                saved = max(0, output_tokens - placeholder_tokens)

                step_copy["output"] = placeholder
                step_copy["compacted"] = True
                pruned_count += 1
                tokens_saved += saved
                accumulated_tokens += placeholder_tokens
                processed_steps.append(step_copy)

        # Restore original chronological order
        processed_steps.reverse()

        return PruneResult(
            steps=processed_steps,
            pruned_count=pruned_count,
            tokens_saved=tokens_saved,
            total_tokens=accumulated_tokens,
        )

    def compact_history_with_retained_tail(
        self,
        messages: List[Dict[str, Any]],
        summary_text: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Preserves the retained tail of recent messages and condenses older messages
        into a structured summary header.
        """
        if len(messages) <= self.messages_to_keep_unsummarized:
            return messages, False

        older_messages = messages[:-self.messages_to_keep_unsummarized]
        retained_tail = messages[-self.messages_to_keep_unsummarized:]

        # Create structured summary of older messages if none provided
        if not summary_text:
            summary_points = []
            for msg in older_messages:
                role = msg.get("role", "system")
                content = str(msg.get("content", ""))[:150]
                summary_points.append(f"- {role.upper()}: {content}")
            summary_text = (
                "[Prior Investigation Context Compacted]\n"
                + "\n".join(summary_points[:10])
            )

        summary_msg = {
            "role": "system",
            "content": f"## Prior Investigation Summary\n{summary_text}",
            "compacted_summary": True,
        }

        return [summary_msg] + retained_tail, True
