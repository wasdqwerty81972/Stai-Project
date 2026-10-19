"""Best-effort JSON extraction from a model's text reply.

Models asked for a single JSON object routinely wrap it in prose ("Here is my
decision: {...}") or emit a fenced block, so callers cannot just
``json.loads`` the reply. The previous implementation searched for the first
``{`` through the last ``}`` with a greedy regex: when the prose around the
object itself contained braces — or the model emitted two objects — that span
was not valid JSON, so the parse raised and the caller silently fell back to a
non-model decision. This module extracts the JSON *values* instead and returns
the first one that actually decodes.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

# ```json ... ``` fences, and ``` ... ``` fences the model mislabels.
_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\s*\n(.*?)```", re.DOTALL)


def _scan_objects(text: str) -> list[str]:
    """Every balanced ``{...}`` span in ``text``, outermost only.

    Brace counting is string-aware so a ``}`` inside a JSON string literal does
    not end the span early.
    """
    spans: list[str] = []
    start = -1
    depth = 0
    in_string = False
    escaped = False

    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0 and start >= 0:
                spans.append(text[start : index + 1])
                start = -1

    return spans


def _decode(candidate: str) -> Optional[Any]:
    try:
        return json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        return None


def extract_json_object(text: Optional[str]) -> Optional[dict[str, Any]]:
    """Return the first JSON object in ``text``, or ``None``.

    Tries, in order: the whole string, each fenced block, then each balanced
    brace span from last to first. Later objects win over earlier prose spans
    because a model that restates the request before answering is far more
    common than one that emits several candidate answers.
    """
    if not text or not text.strip():
        return None

    whole = _decode(text.strip())
    if isinstance(whole, dict):
        return whole

    candidates: list[str] = []
    for block in _FENCE_RE.findall(text):
        stripped = block.strip()
        candidates.extend(_scan_objects(stripped))
        if not _scan_objects(stripped):
            decoded = _decode(stripped)
            if isinstance(decoded, dict):
                return decoded

    for span in reversed(_scan_objects(text)):
        decoded = _decode(span)
        if isinstance(decoded, dict):
            return decoded

    for span in reversed(candidates):
        decoded = _decode(span)
        if isinstance(decoded, dict):
            return decoded

    return None


_FAILURE_MARKERS = ("[AI ERROR]", "[LLM error]", "[LLM unavailable]")


def is_ai_error_marker(text: Optional[str]) -> bool:
    """True when ``text`` is a provider-failure sentinel, not model output.

    Callers return a marker string on exception rather than raising, so every
    string-returning caller has to decide what a failure means. Treating one as
    a reply hands the user an infrastructure error in place of an answer or a
    decision.

    All three markers are covered because they come from different backends:
    ``CyberAgent``'s role callers emit ``[AI ERROR]``, and ``LLMClient`` in
    ``cyber_os.tool_orchestrator`` — which ``AgentRuntime._call_llm`` falls back
    to when the orchestrator exposes no ``_call_role`` — emits ``[LLM error]``
    or ``[LLM unavailable]``.
    """
    if not text:
        return False
    return str(text).lstrip().startswith(_FAILURE_MARKERS)