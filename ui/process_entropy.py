"""Bounded entropy sampling for process executable files."""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path


def executable_entropy(path: str | Path, *, sample_bytes: int = 1_048_576) -> float:
    """Return sampled Shannon entropy in bits per byte (0 to 8).

    Large files are sampled from up to four evenly spaced windows. This is a
    triage signal only; a high score must be followed by the configured scanner.
    """
    limit = max(1, int(sample_bytes))
    file_path = Path(path)
    size = file_path.stat().st_size
    if size <= 0:
        return 0.0
    window_count = 1 if size <= limit else min(4, limit, max(1, size // 65_536))
    window_size = max(1, limit // window_count)
    offsets = [0] if size <= limit else [
        int((size - window_size) * index / max(1, window_count - 1))
        for index in range(window_count)
    ]
    counts: Counter[int] = Counter()
    total = 0
    with file_path.open("rb") as source:
        for offset in offsets:
            source.seek(offset)
            chunk = source.read(min(window_size, limit - total))
            counts.update(chunk)
            total += len(chunk)
            if total >= limit:
                break
    if total == 0:
        return 0.0
    entropy = math.log2(total) - sum(count * math.log2(count) for count in counts.values()) / total
    return round(min(8.0, max(0.0, entropy)), 4)
