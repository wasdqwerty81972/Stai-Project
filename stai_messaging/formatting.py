"""Platform-neutral helpers for bounded, plain-text outbound messages."""

from __future__ import annotations


def split_text(text: str, limit: int) -> list[str]:
    """Split text without dropping characters or exceeding the platform limit."""
    if limit < 1:
        raise ValueError("limit must be positive")
    if not text:
        return [""]
    parts: list[str] = []
    remaining = text
    while len(remaining) > limit:
        boundary = remaining.rfind("\n", 0, limit + 1)
        if boundary < limit // 2:
            boundary = remaining.rfind(" ", 0, limit + 1)
        if boundary < limit // 2:
            boundary = limit
        split_at = boundary + 1 if boundary < limit else boundary
        parts.append(remaining[:split_at])
        remaining = remaining[split_at:]
    if remaining:
        parts.append(remaining)
    return parts
