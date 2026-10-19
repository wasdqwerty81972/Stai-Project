"""
cyber_os/assets/frontmatter.py — YAML frontmatter parsing for markdown assets.

Commands, skills, and subagent definitions all use the same shape: a YAML
mapping delimited by ``---`` lines, followed by a markdown body. This module is
the single parser for all three so their loaders cannot drift apart.

Parsing is deliberately forgiving. A malformed or absent frontmatter block
yields an empty mapping and the whole file as the body rather than raising: one
bad asset file must not take down discovery for the other few hundred.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

import yaml

_FRONTMATTER_RE = re.compile(
    r"\A---[ \t]*\r?\n(?P<front>.*?)\r?\n---[ \t]*\r?\n?(?P<body>.*)\Z",
    re.DOTALL,
)


def split_frontmatter(text: str) -> Tuple[Dict[str, Any], str]:
    """Return ``(frontmatter_mapping, body)`` for a markdown asset.

    A leading UTF-8 BOM is discarded first. ``\\A---`` does not match when one
    precedes the delimiter, so a BOM used to make the whole block invisible:
    every subagent definition and half the skills parsed as "no frontmatter",
    losing their declared tools, model, and description without any error. The
    forgiving parse above is what made that silent, so the BOM is stripped here
    rather than at each of the three call sites.
    """
    text = text.lstrip("﻿")
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text

    try:
        front = yaml.safe_load(match.group("front"))
    except yaml.YAMLError:
        return {}, text

    if not isinstance(front, dict):
        return {}, text

    return front, match.group("body")


def as_text(value: Any, default: str = "") -> str:
    """Coerce a frontmatter scalar to a stripped string."""
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def as_bool(value: Any, default: bool = False) -> bool:
    """Coerce a frontmatter scalar to a bool, tolerating YAML string forms."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "on"}:
            return True
        if lowered in {"false", "no", "0", "off"}:
            return False
    return default


def as_list(value: Any) -> List[str]:
    """Coerce a frontmatter value to a list of non-empty strings.

    Accepts a YAML list, or the comma-separated single-line form that Claude
    Code style agent definitions use (``tools: Read, Grep, Glob``).
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        items: List[str] = []
        for entry in value:
            text = as_text(entry)
            if text:
                items.append(text)
        return items
    text = as_text(value)
    return [text] if text else []
