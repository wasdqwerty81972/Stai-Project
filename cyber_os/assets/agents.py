"""
cyber_os/assets/agents.py — Markdown subagent definition discovery.

A definition is a markdown file in ``subagents/definitions/``: frontmatter with
a name, description, declared tool access and preferred model, plus a body that
becomes the subagent's system prompt.

These definitions declare tools in Claude Code's vocabulary, so
:mod:`cyber_os.assets.tool_map` translates them to SVS registry names. A
definition is then validated against the live ``ToolRegistry``:

* tools that translate and exist become the subagent's allowlist;
* tools that translate but are not registered are reported as ``missing_tools``;
* tools with no SVS equivalent are reported as ``unmapped_tools``.

Nothing is silently dropped. SVS's hand-written profiles already name four
tools that do not exist in the registry, and the point of validating here is
that a markdown-loaded definition cannot add to that quietly.

Definitions complement, and never replace, the ten hand-written specialists in
``cyber_os/subagents/profiles.py``: on a name clash the hand-written profile
wins, because it is the one with a curated defensive-security allowlist.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from cyber_os.assets import paths
from cyber_os.assets.frontmatter import as_list, as_text, split_frontmatter
from cyber_os.assets.tool_map import explain_unmapped, filter_to_registered, translate

# Step budget for a markdown-defined subagent. Matches the mid-range of the
# hand-written specialists so a definition cannot out-spend them by default.
DEFAULT_MAX_STEPS = 10


@dataclass
class AgentDefinition:
    """One markdown subagent definition."""

    name: str
    description: str
    source_path: Path
    model: Optional[str] = None
    declared_tools: List[str] = field(default_factory=list)
    allowed_tools: List[str] = field(default_factory=list)
    missing_tools: List[str] = field(default_factory=list)
    unmapped_tools: List[str] = field(default_factory=list)
    max_steps: int = DEFAULT_MAX_STEPS
    _system_prompt: Optional[str] = field(default=None, repr=False)

    def system_prompt(self) -> str:
        """Return the body, reading it from disk on first access."""
        if self._system_prompt is None:
            try:
                text = self.source_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self._system_prompt = f"[definition body unavailable: {exc}]"
            else:
                _, body = split_frontmatter(text)
                self._system_prompt = body.strip()
        return self._system_prompt

    def capability_notes(self) -> List[str]:
        """Human-readable notes on capabilities this definition cannot get."""
        notes = [
            f"{name}: {explain_unmapped(name)}" for name in self.unmapped_tools
        ]
        notes.extend(
            f"{name}: declared but not registered in this deployment"
            for name in self.missing_tools
        )
        return notes

    def to_manifest(self) -> Dict[str, Any]:
        """Summarise the definition without reading its body."""
        return {
            "name": self.name,
            "description": self.description,
            "model": self.model,
            "allowed_tools": list(self.allowed_tools),
            "declared_tools": list(self.declared_tools),
            "unmapped_tools": list(self.unmapped_tools),
            "missing_tools": list(self.missing_tools),
            "max_steps": self.max_steps,
            "origin": "markdown_definition",
        }


class AgentDefinitionRegistry:
    """Discovers the markdown subagent definitions under ``subagents/definitions/``."""

    def __init__(self, directory: Optional[Path] = None) -> None:
        self._directory = (
            Path(directory) if directory else paths.agent_definitions_dir()
        )
        self._definitions: Dict[str, AgentDefinition] = {}
        self._registered_tools: List[str] = []
        self._lock = threading.Lock()
        self._loaded = False

    @property
    def directory(self) -> Path:
        return self._directory

    def load(
        self,
        registered_tools: Optional[Iterable[str]] = None,
        force: bool = False,
    ) -> None:
        """Scan the definitions directory and validate declared tool access.

        ``registered_tools`` should be the live ``ToolRegistry`` keys. When it
        is omitted, translation still runs but no availability check is made,
        so ``missing_tools`` stays empty rather than reporting false absences.
        """
        with self._lock:
            if self._loaded and not force and registered_tools is None:
                return

            if registered_tools is not None:
                self._registered_tools = sorted(registered_tools)

            discovered: Dict[str, AgentDefinition] = {}
            if self._directory.is_dir():
                for path in sorted(self._directory.glob("*.md")):
                    definition = self._read(path, self._registered_tools)
                    if definition is not None:
                        discovered[definition.name] = definition

            self._definitions = discovered
            self._loaded = True

    @staticmethod
    def _read(
        path: Path,
        registered_tools: List[str],
    ) -> Optional[AgentDefinition]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        front, _ = split_frontmatter(text)
        name = as_text(front.get("name")) or path.stem
        declared = as_list(front.get("tools"))

        translated, unmapped = translate(declared)
        if registered_tools:
            allowed, missing = filter_to_registered(translated, registered_tools)
        else:
            allowed, missing = list(translated), []

        return AgentDefinition(
            name=name,
            description=as_text(front.get("description")),
            source_path=path,
            model=as_text(front.get("model")) or None,
            declared_tools=declared,
            allowed_tools=allowed,
            missing_tools=missing,
            unmapped_tools=unmapped,
        )

    def all(self) -> List[AgentDefinition]:
        self.load()
        return [self._definitions[name] for name in sorted(self._definitions)]

    def names(self) -> List[str]:
        self.load()
        return sorted(self._definitions)

    def get(self, name: str) -> Optional[AgentDefinition]:
        self.load()
        cleaned = (name or "").strip()
        direct = self._definitions.get(cleaned)
        if direct is not None:
            return direct
        folded = cleaned.lower().replace("_", "-")
        for candidate, definition in self._definitions.items():
            if candidate.lower().replace("_", "-") == folded:
                return definition
        return None

    def search(self, query: str, limit: int = 10) -> List[AgentDefinition]:
        """Rank definitions by term overlap against name and description."""
        self.load()
        terms = [term for term in (query or "").lower().split() if term]
        if not terms:
            return self.all()[:limit]

        scored: List[tuple[int, str, AgentDefinition]] = []
        for definition in self._definitions.values():
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
        """Manifests for every definition, for tool results and UI listings."""
        return [definition.to_manifest() for definition in self.all()]


_REGISTRY: Optional[AgentDefinitionRegistry] = None
_REGISTRY_LOCK = threading.Lock()


def get_agent_definition_registry() -> AgentDefinitionRegistry:
    """Return the process-wide markdown subagent definition registry."""
    global _REGISTRY
    with _REGISTRY_LOCK:
        if _REGISTRY is None:
            _REGISTRY = AgentDefinitionRegistry()
        return _REGISTRY
