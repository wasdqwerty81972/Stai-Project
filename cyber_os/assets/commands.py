"""
cyber_os/assets/commands.py — Markdown command discovery and expansion.

A command is a markdown file in ``commands/``. Its frontmatter carries the
description, an optional argument hint, and optional routing (``agent``,
``subtask``, ``model``); its body is the prompt.

``/name arguments`` typed by an operator is expanded here into the command's
prompt before the orchestrator classifies intent, so a command reaches the
model as a full instruction rather than as the literal four characters the
operator typed. Expansion happens once, at
``ToolOrchestrator.handle_message``, which is the single entry point every
surface (desktop workspace and the FastAPI ``/api/chat`` route) already calls.

Bodies are read lazily. There are ~100 commands and a session normally invokes
none of them, so discovery reads frontmatter only.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyber_os.assets import paths
from cyber_os.assets.frontmatter import as_bool, as_text, split_frontmatter

# Placeholder the ECC command bodies use for operator-supplied arguments.
ARGUMENTS_PLACEHOLDER = "$ARGUMENTS"


@dataclass
class CommandDefinition:
    """One markdown command."""

    name: str
    description: str
    source_path: Path
    argument_hint: str = ""
    agent: Optional[str] = None
    subtask: bool = False
    model: Optional[str] = None
    _body: Optional[str] = field(default=None, repr=False)

    def body(self) -> str:
        """Return the prompt body, reading it from disk on first access."""
        if self._body is None:
            try:
                text = self.source_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                self._body = f"[command body unavailable: {exc}]"
            else:
                _, body = split_frontmatter(text)
                self._body = body.strip()
        return self._body

    def render(self, arguments: str = "") -> str:
        """Return the prompt with operator arguments substituted."""
        prompt = self.body()
        arguments = (arguments or "").strip()

        if ARGUMENTS_PLACEHOLDER in prompt:
            return prompt.replace(ARGUMENTS_PLACEHOLDER, arguments)
        if arguments:
            return f"{prompt}\n\n{arguments}"
        return prompt

    def to_manifest(self) -> Dict[str, Any]:
        """Summarise the command without reading its body."""
        return {
            "name": self.name,
            "description": self.description,
            "argument_hint": self.argument_hint,
            "agent": self.agent,
            "subtask": self.subtask,
            "model": self.model,
        }


@dataclass
class ExpandedCommand:
    """The result of expanding an operator's ``/name arguments`` input."""

    name: str
    prompt: str
    arguments: str
    definition: CommandDefinition


class CommandRegistry:
    """Discovers and expands the markdown commands in ``commands/``."""

    def __init__(self, directory: Optional[Path] = None) -> None:
        self._directory = Path(directory) if directory else paths.commands_dir()
        self._commands: Dict[str, CommandDefinition] = {}
        self._lock = threading.Lock()
        self._loaded = False

    @property
    def directory(self) -> Path:
        return self._directory

    def load(self, force: bool = False) -> None:
        """Scan the command directory. Idempotent unless ``force`` is set."""
        with self._lock:
            if self._loaded and not force:
                return

            discovered: Dict[str, CommandDefinition] = {}
            if self._directory.is_dir():
                for path in sorted(self._directory.glob("*.md")):
                    definition = self._read(path)
                    if definition is not None:
                        discovered[definition.name] = definition

            self._commands = discovered
            self._loaded = True

    @staticmethod
    def _read(path: Path) -> Optional[CommandDefinition]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        front, _ = split_frontmatter(text)
        name = as_text(front.get("name")) or path.stem

        return CommandDefinition(
            name=name,
            description=as_text(front.get("description")) or name.replace("-", " "),
            source_path=path,
            argument_hint=as_text(front.get("argument-hint"))
            or as_text(front.get("argument_hint")),
            agent=as_text(front.get("agent")) or None,
            subtask=as_bool(front.get("subtask")),
            model=as_text(front.get("model")) or None,
        )

    def all(self) -> List[CommandDefinition]:
        self.load()
        return [self._commands[name] for name in sorted(self._commands)]

    def names(self) -> List[str]:
        self.load()
        return sorted(self._commands)

    def get(self, name: str) -> Optional[CommandDefinition]:
        self.load()
        return self._commands.get(self._normalise(name))

    def index(self) -> List[Dict[str, Any]]:
        """Manifests for every command, for tool results and UI listings."""
        return [definition.to_manifest() for definition in self.all()]

    def expand(self, text: str) -> Optional[ExpandedCommand]:
        """Expand ``/name arguments`` into a prompt.

        Returns ``None`` when ``text`` is not a slash command or names a
        command that does not exist, so callers can fall through to normal
        message handling rather than failing the turn.
        """
        if not text:
            return None

        stripped = text.lstrip()
        if not stripped.startswith("/"):
            return None

        invocation = stripped[1:]
        if not invocation or invocation[0].isspace():
            return None

        head, _, tail = invocation.partition(" ")
        definition = self.get(head)
        if definition is None:
            return None

        arguments = tail.strip()
        return ExpandedCommand(
            name=definition.name,
            prompt=definition.render(arguments),
            arguments=arguments,
            definition=definition,
        )

    @staticmethod
    def _normalise(name: str) -> str:
        cleaned = (name or "").strip()
        if cleaned.startswith("/"):
            cleaned = cleaned[1:]
        if cleaned.endswith(".md"):
            cleaned = cleaned[: -len(".md")]
        return cleaned


_REGISTRY: Optional[CommandRegistry] = None
_REGISTRY_LOCK = threading.Lock()


def get_command_registry() -> CommandRegistry:
    """Return the process-wide command registry."""
    global _REGISTRY
    with _REGISTRY_LOCK:
        if _REGISTRY is None:
            _REGISTRY = CommandRegistry()
        return _REGISTRY
