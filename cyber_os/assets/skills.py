"""
cyber_os/assets/skills.py — Skill bundle discovery.

A skill is a directory under ``skills/`` containing ``SKILL.md`` — frontmatter
with a name and description, plus a markdown body of instructions — and
optionally supporting files (scripts, references, templates).

There are ~300 skills. Injecting every body, or even every description, into
the system prompt would dominate the context window, so discovery is
search-first: the agent calls ``skill_search`` to find a relevant skill by
description, then ``skill_read`` to pull that one body in. Only frontmatter is
read at load time; bodies are read on demand and cached.

Supporting files are resolved relative to the skill's own directory, so a skill
that references ``scripts/run.py`` keeps working from this canonical location
without any path pointing back at the read-only source checkouts.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyber_os.assets import paths
from cyber_os.assets.frontmatter import as_list, as_text, split_frontmatter

# Cap on resource listings so a skill shipping a large reference tree cannot
# produce an unbounded tool result.
MAX_LISTED_RESOURCES = 40


@dataclass
class SkillDefinition:
    """One skill bundle."""

    name: str
    description: str
    directory: Path
    skill_file: Path
    allowed_tools: List[str] = field(default_factory=list)
    _body: Optional[str] = field(default=None, repr=False)

    def body(self) -> str:
        """Return the instruction body, reading it from disk on first access."""
        if self._body is None:
            try:
                text = self.skill_file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self._body = f"[skill body unavailable: {exc}]"
            else:
                _, body = split_frontmatter(text)
                self._body = body.strip()
        return self._body

    def resources(self) -> List[str]:
        """List supporting files, as paths relative to the skill directory."""
        if not self.directory.is_dir():
            return []

        found: List[str] = []
        for path in sorted(self.directory.rglob("*")):
            if not path.is_file() or path == self.skill_file:
                continue
            if "__pycache__" in path.parts or path.name.startswith("."):
                continue
            found.append(path.relative_to(self.directory).as_posix())
            if len(found) >= MAX_LISTED_RESOURCES:
                break
        return found

    def to_manifest(self) -> Dict[str, Any]:
        """Summarise the skill without reading its body."""
        return {
            "name": self.name,
            "description": self.description,
            "allowed_tools": list(self.allowed_tools),
        }


class SkillRegistry:
    """Discovers the skill bundles under ``skills/``."""

    def __init__(self, directory: Optional[Path] = None) -> None:
        self._directory = Path(directory) if directory else paths.skills_dir()
        self._skills: Dict[str, SkillDefinition] = {}
        self._lock = threading.Lock()
        self._loaded = False

    @property
    def directory(self) -> Path:
        return self._directory

    def load(self, force: bool = False) -> None:
        """Scan the skills directory. Idempotent unless ``force`` is set."""
        with self._lock:
            if self._loaded and not force:
                return

            discovered: Dict[str, SkillDefinition] = {}
            if self._directory.is_dir():
                for child in sorted(self._directory.iterdir()):
                    if not child.is_dir() or child.name.startswith("."):
                        continue
                    definition = self._read(child)
                    if definition is not None:
                        discovered[definition.name] = definition

            self._skills = discovered
            self._loaded = True

    @staticmethod
    def _read(directory: Path) -> Optional[SkillDefinition]:
        skill_file = directory / "SKILL.md"
        if not skill_file.is_file():
            return None

        try:
            text = skill_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        front, _ = split_frontmatter(text)
        name = as_text(front.get("name")) or directory.name

        return SkillDefinition(
            name=name,
            description=as_text(front.get("description")),
            directory=directory,
            skill_file=skill_file,
            allowed_tools=as_list(front.get("allowed-tools"))
            or as_list(front.get("allowed_tools")),
        )

    def all(self) -> List[SkillDefinition]:
        self.load()
        return [self._skills[name] for name in sorted(self._skills)]

    def names(self) -> List[str]:
        self.load()
        return sorted(self._skills)

    def get(self, name: str) -> Optional[SkillDefinition]:
        self.load()
        cleaned = (name or "").strip()
        direct = self._skills.get(cleaned)
        if direct is not None:
            return direct
        # Tolerate case and separator drift between prose and directory names.
        folded = cleaned.lower().replace("_", "-")
        for candidate, definition in self._skills.items():
            if candidate.lower().replace("_", "-") == folded:
                return definition
        return None

    def search(self, query: str, limit: int = 10) -> List[SkillDefinition]:
        """Rank skills by term overlap against name and description.

        A plain substring scan is enough at this scale and keeps discovery
        dependency-free; the agent refines by reading the candidates it gets.
        """
        self.load()
        terms = [term for term in (query or "").lower().split() if term]
        if not terms:
            return self.all()[:limit]

        scored: List[tuple[int, str, SkillDefinition]] = []
        for definition in self._skills.values():
            haystack_name = definition.name.lower().replace("-", " ")
            haystack_desc = definition.description.lower()
            score = 0
            for term in terms:
                if term in haystack_name:
                    score += 3
                if term in haystack_desc:
                    score += 1
            if score:
                scored.append((score, definition.name, definition))

        scored.sort(key=lambda row: (-row[0], row[1]))
        return [definition for _, _, definition in scored[:limit]]

    def index(self) -> List[Dict[str, Any]]:
        """Manifests for every skill, for tool results and UI listings."""
        return [definition.to_manifest() for definition in self.all()]


_REGISTRY: Optional[SkillRegistry] = None
_REGISTRY_LOCK = threading.Lock()


def get_skill_registry() -> SkillRegistry:
    """Return the process-wide skill registry."""
    global _REGISTRY
    with _REGISTRY_LOCK:
        if _REGISTRY is None:
            _REGISTRY = SkillRegistry()
        return _REGISTRY
