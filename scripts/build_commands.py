#!/usr/bin/env python3
"""Assemble the canonical top-level ``commands/`` directory.

Sources are READ-ONLY. Files are copied out of them, never modified in place.

Merge rules
-----------
* ``ECC-source/commands/*.md`` is canonical: these are the long-form command
  bodies (e.g. code-review.md is 289 lines vs the 68-line OpenCode variant).
* ``ECC-source/.opencode/commands/*.md`` carries routing frontmatter the
  canonical files lack (``agent:``, ``subtask:``, ``model:``). Where a command
  exists in both, the canonical body wins and the routing keys are merged in.
* Commands that exist only in ``.opencode/commands`` or ``.claude/commands``
  are copied as-is.
* The project's pre-existing STAI commands are kept under a ``stai-`` prefix so
  their project-specific intent survives without shadowing ECC's fuller
  versions of the same name.
"""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ECC = ROOT / "ECC-source"
DEST = ROOT / "commands"

# Routing keys that only the OpenCode variants define and that are worth
# carrying over onto the canonical long-form body.
ROUTING_KEYS = ("agent", "subtask", "model", "temperature")


def split_frontmatter(text: str) -> tuple[list[str], str]:
    """Return (frontmatter_lines, body). Missing frontmatter yields ([], text)."""
    if not text.startswith("---"):
        return [], text
    lines = text.splitlines(keepends=True)
    for index in range(1, len(lines)):
        if lines[index].rstrip("\r\n") == "---":
            return lines[1:index], "".join(lines[index + 1 :])
    return [], text


def routing_from(text: str) -> dict[str, str]:
    front, _ = split_frontmatter(text)
    found: dict[str, str] = {}
    for line in front:
        key, sep, value = line.partition(":")
        if sep and key.strip() in ROUTING_KEYS:
            found[key.strip()] = value.strip()
    return found


def merge_routing(canonical: str, routing: dict[str, str]) -> str:
    """Inject routing keys into canonical's frontmatter without clobbering it."""
    if not routing:
        return canonical
    front, body = split_frontmatter(canonical)
    if not front:
        # No frontmatter at all: synthesise one so the routing survives.
        block = "".join(f"{k}: {v}\n" for k, v in routing.items())
        return f"---\n{block}---\n\n{canonical}"
    present = {line.partition(":")[0].strip() for line in front}
    added = [f"{k}: {v}\n" for k, v in routing.items() if k not in present]
    return "---\n" + "".join(front) + "".join(added) + "---\n" + body


def main() -> None:
    DEST.mkdir(exist_ok=True)

    canonical_dir = ECC / "commands"
    opencode_dir = ECC / ".opencode" / "commands"
    claude_dir = ECC / ".claude" / "commands"

    canonical = {p.name for p in canonical_dir.glob("*.md")}
    opencode = {p.name for p in opencode_dir.glob("*.md")}
    claude = {p.name for p in claude_dir.glob("*.md")}

    merged = copied = 0

    # 1. Canonical ECC commands, with OpenCode routing merged where available.
    for name in sorted(canonical):
        text = (canonical_dir / name).read_text(encoding="utf-8")
        if name in opencode:
            routing = routing_from((opencode_dir / name).read_text(encoding="utf-8"))
            new_text = merge_routing(text, routing)
            if new_text != text:
                merged += 1
            text = new_text
        (DEST / name).write_text(text, encoding="utf-8")
        copied += 1

    # 2. Commands unique to the OpenCode / Claude command sets.
    extra = 0
    for source_dir, names in ((opencode_dir, opencode - canonical), (claude_dir, claude - canonical)):
        for name in sorted(names):
            shutil.copy2(source_dir / name, DEST / name)
            extra += 1

    # 3. Project-local STAI commands, namespaced to avoid shadowing ECC.
    project = ROOT / ".claude" / "commands"
    renamed = 0
    if project.is_dir():
        for path in sorted(project.glob("*.md")):
            target = DEST / f"stai-{path.name}"
            if not target.exists():
                shutil.copy2(path, target)
                renamed += 1

    total = len(list(DEST.glob("*.md")))
    print(f"canonical copied : {copied}")
    print(f"routing merged   : {merged}")
    print(f"unique added     : {extra}")
    print(f"stai- namespaced : {renamed}")
    print(f"TOTAL in commands/: {total}")


if __name__ == "__main__":
    main()
