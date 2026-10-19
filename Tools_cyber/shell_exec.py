"""
Unified shell execution tool — the single entry point that replaces the 59
per-CLI wrapper tools.

Two invocation modes share one tool so the agent has *one* way to run a command
instead of dozens of near-identical wrappers:

1. **Preset mode** — ``preset="<id>"`` plus ``params={...}``. The id names an
   entry in :data:`cyber_os.command_presets.COMMAND_PRESETS` (the frozen,
   vetted argv templates the old wrappers were generated from). Placeholders are
   substituted with interpreter-correct quoting so a parameter value can never
   change the command's *structure* — it stays data, never a second command.

2. **Free-form mode** — ``command="<string>"`` plus ``environment`` in
   ``{"powershell","wsl","cmd"}``. Any raw command the agent composes itself.

Risk is decided per-invocation by :func:`resolve_risk` (wired into the executor
as the tool's ``risk_classifier``), never by a static label:

* Free-form commands are classified by
  :func:`cyber_os.policy.command_classifier.classify_command`. An interpreter
  command can never earn ``READ_ONLY`` — the classifier only awards it to an
  exact allow-list match with nothing refused/undecidable — so a hand-written
  command always requires approval unless it is a recognised safe read.
* Preset commands carry a vetted frozen risk, but the *final substituted string*
  is **also** run through the classifier and the worst of the two wins. That is
  the belt-and-braces: even if substitution had a quoting bug, an injected
  ``; rm -rf`` in the final string escalates the verdict to ``DESTRUCTIVE`` and
  forces human approval.

Any error, a missing parameter, or an unknown preset fails **closed** to
``DESTRUCTIVE`` — a tool that cannot decide its own blast radius must not run
unattended.

A command whose shell reports the binary missing — exit 127 / ``command not
found`` (bash), ``is not recognized as an internal or external command``
(cmd.exe), ``is not recognized as the name of a cmdlet`` (PowerShell) — returns
``{"success": False, "status": "tool_absent", "binary": ..., "env": ...,
"hint": ...}`` rather than an empty result that merely looks like a failed run,
so an absent scanner can never be read as a clean scan.

Usage (via CyberToolsClient):
    call shell_exec --input '{"preset": "nmap_scan", "params": {"target": "10.0.0.1"}}'
    call shell_exec --input '{"command": "Get-Process", "environment": "powershell"}'
"""
from __future__ import annotations

import re
import shlex
from typing import Any, Dict, List, Optional, Tuple

from cyber_tools import CyberToolPlugin, RiskLevel, execute_system_command

# The preset catalogue and the classifier live in cyber_os; import defensively so
# a partially-installed checkout degrades to "fail closed" rather than crashing
# the whole registry at import time.
try:
    from cyber_os.command_presets import COMMAND_PRESETS, CommandPreset
except Exception:  # pragma: no cover - only when cyber_os is unavailable
    COMMAND_PRESETS = {}  # type: ignore[assignment]
    CommandPreset = Any  # type: ignore[assignment,misc]

try:
    from cyber_os.policy.command_classifier import classify_command
except Exception:  # pragma: no cover
    classify_command = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_ENVIRONMENTS = ("powershell", "wsl", "cmd")

# execute_system_command environment -> classifier interpreter name.
_ENV_TO_INTERPRETER: Dict[str, str] = {
    "powershell": "powershell",
    "wsl": "bash",
    "cmd": "cmd",
}

# Ascending blast radius. Used to take the worst of two verdicts.
_RISK_RANK: Dict[RiskLevel, int] = {
    RiskLevel.READ_ONLY: 0,
    RiskLevel.MODIFIES_SYSTEM: 1,
    RiskLevel.DESTRUCTIVE: 2,
    RiskLevel.KERNEL_INTERVENTION: 3,
}

# Argv heads that mean "this is really a PowerShell command", regardless of the
# preset's declared platform. ``&`` is the PowerShell call operator (the old
# executor special-cased windows_defender_scan -> powershell for exactly this).
_POWERSHELL_HEADS = {"powershell", "pwsh", "&"}

# PowerShell arguments after which the *next* argv element is the script body.
_PS_COMMAND_FLAGS = {"-command", "-c", "-encodedcommand"}

# Matches a placeholder, optionally wrapped in one layer of matching quotes:
#   {target}   '{target}'   "{target}"
# The captured group 1 is the opening quote (if any); the backreference \1
# requires the same closing quote, so mismatched quotes are left untouched.
_PLACEHOLDER_RE = re.compile(r"""(['"]?)\{(\w+)\}\1""")


class MissingParameterError(KeyError):
    """A preset placeholder had no matching value in ``params``."""


class UnknownPresetError(KeyError):
    """The requested preset id is not in the catalogue."""


# ---------------------------------------------------------------------------
# Quoting — each interpreter gets a value form that cannot break out of "data".
# ---------------------------------------------------------------------------

def _quote(value: str, interpreter: str) -> str:
    """Return ``value`` as a single quoted token for ``interpreter``.

    The result is always exactly one shell token: no embedded whitespace,
    metacharacter, or quote can split it into a second argument or command.
    """
    if "\x00" in value:
        # A NUL byte is never a legitimate argument; refuse to build the command.
        raise ValueError("parameter value contains a NUL byte")

    if interpreter == "bash":
        return shlex.quote(value)

    if interpreter == "powershell":
        # A single-quoted PowerShell literal; the only escape inside it is '' for '.
        return "'" + value.replace("'", "''") + "'"

    # cmd.exe has no robust quoting story; wrap in double quotes, double any
    # embedded quote, and strip the two characters cmd expands even inside
    # quotes (% and !) so a value can never trigger variable expansion. The
    # classifier remains the floor for anything that slips through.
    sanitized = value.replace('"', '""').replace("%", "").replace("!", "")
    return '"' + sanitized + '"'


def _substitute(segment: str, params: Dict[str, Any], interpreter: str) -> str:
    """Substitute every ``{name}`` in ``segment`` with a quoted param value.

    Any surrounding single layer of matching quotes the template author wrote is
    replaced by canonical quoting, so the author's intent ("this is a quoted
    literal") is preserved without double-quoting.
    """

    def _repl(match: "re.Match[str]") -> str:
        name = match.group(2)
        if name not in params:
            raise MissingParameterError(name)
        return _quote(str(params[name]), interpreter)

    return _PLACEHOLDER_RE.sub(_repl, segment)


# ---------------------------------------------------------------------------
# Preset -> concrete (command, environment, interpreter)
# ---------------------------------------------------------------------------

def _execution_env(preset: "CommandPreset") -> str:
    """Pick the execute_system_command environment a preset should run in."""
    head = str(preset.argv_template[0]).lower() if preset.argv_template else ""
    if head in _POWERSHELL_HEADS:
        return "powershell"

    env = preset.env
    env_name = env[0] if isinstance(env, list) and env else env
    if env_name == "wsl_linux":
        return "wsl"
    # native_windows and cross_platform non-PowerShell binaries run through cmd,
    # matching how the old executor routed them.
    return "cmd"


def _unwrap_powershell_script(argv: List[str]) -> str:
    """Extract the script body from a ``powershell -Command "<script>"`` argv.

    execute_system_command already prepends ``-NoProfile -NonInteractive
    -Command``, so we return only the script itself (with one surrounding layer
    of double quotes stripped). ``&``-led argv (the call operator) has no
    -Command flag; its whole tail is the script.
    """
    lowered = [a.lower() for a in argv]
    for flag in _PS_COMMAND_FLAGS:
        if flag in lowered:
            idx = lowered.index(flag)
            if idx + 1 < len(argv):
                body = argv[idx + 1]
                if len(body) >= 2 and body[0] == body[-1] == '"':
                    body = body[1:-1]
                return body
    # No -Command flag (e.g. the '&' call operator form): join everything.
    return " ".join(argv)


def build_preset_command(preset_id: str, params: Optional[Dict[str, Any]]) -> Tuple[str, str, str]:
    """Resolve a preset id + params into ``(command, environment, interpreter)``.

    Raises :class:`UnknownPresetError` for a bad id and
    :class:`MissingParameterError` when a required placeholder is unfilled.
    """
    preset = COMMAND_PRESETS.get(preset_id)
    if preset is None:
        raise UnknownPresetError(preset_id)

    params = params or {}
    environment = _execution_env(preset)
    interpreter = _ENV_TO_INTERPRETER[environment]

    if environment == "powershell":
        script = _unwrap_powershell_script(list(preset.argv_template))
        command = _substitute(script, params, interpreter)
    else:
        parts = [_substitute(seg, params, interpreter) for seg in preset.argv_template]
        command = " ".join(parts)

    return command, environment, interpreter


# ---------------------------------------------------------------------------
# Risk resolution — this is the tool's risk_classifier.
# ---------------------------------------------------------------------------

def _worst(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    return a if _RISK_RANK.get(a, 99) >= _RISK_RANK.get(b, 99) else b


def _classify_final(command: str, interpreter: str, is_privileged: bool) -> RiskLevel:
    """Classify a concrete command string, mapping the verdict to RiskLevel.

    Fails closed to DESTRUCTIVE if the classifier is unavailable or the verdict
    is undecidable.
    """
    if classify_command is None:
        return RiskLevel.DESTRUCTIVE
    verdict = classify_command(command, interpreter, is_privileged=is_privileged)
    if verdict.undecidable:
        return RiskLevel.DESTRUCTIVE
    try:
        level = RiskLevel[verdict.level]
    except KeyError:
        return RiskLevel.DESTRUCTIVE
    # A command that needs admin is never a silent read-only auto-approval.
    if verdict.requires_admin and level == RiskLevel.READ_ONLY:
        level = RiskLevel.MODIFIES_SYSTEM
    return level


def resolve_risk(**kwargs: Any) -> RiskLevel:
    """Per-invocation risk verdict for shell_exec. Registered as risk_classifier.

    The executor calls this with the resolved tool arguments *before* asking for
    approval, and honours the verdict as the sole risk authority for this tool.
    Any failure returns DESTRUCTIVE so an undecidable call can never slip through
    as auto-approved.
    """
    try:
        preset_id = kwargs.get("preset")
        if preset_id:
            preset = COMMAND_PRESETS.get(str(preset_id))
            if preset is None:
                return RiskLevel.DESTRUCTIVE  # unknown preset -> fail closed
            command, _env, interpreter = build_preset_command(
                str(preset_id), kwargs.get("params")
            )
            try:
                frozen = RiskLevel[preset.risk_level]
            except KeyError:
                frozen = RiskLevel.DESTRUCTIVE
            if preset.requires_admin and frozen == RiskLevel.READ_ONLY:
                frozen = RiskLevel.MODIFIES_SYSTEM
            classified = _classify_final(command, interpreter, preset.requires_admin)
            return _worst(frozen, classified)

        command = str(kwargs.get("command", "")).strip()
        if not command:
            return RiskLevel.DESTRUCTIVE  # nothing to run, but never auto-approve
        environment = str(kwargs.get("environment", "powershell")).lower()
        interpreter = _ENV_TO_INTERPRETER.get(environment, "bash")
        return _classify_final(command, interpreter, is_privileged=False)
    except Exception:
        # Belt and braces: any unexpected failure is treated as maximally risky.
        return RiskLevel.DESTRUCTIVE


class ShellExecTool(CyberToolPlugin):
    """Execute a preset or free-form command in PowerShell, WSL bash, or CMD."""

    name = "shell_exec"
    description = (
        "Run a shell command. Either pass preset=<id> + params={...} to run one "
        "of the vetted CLI presets (e.g. nmap_scan, get_winevent), or command=<str> "
        "+ environment in {powershell,wsl,cmd} for a free-form command. Risk is "
        "decided per call by the command classifier; free-form commands are never "
        "auto-approved as read-only."
    )
    version = "2.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    # Static label for the manifest only. The real authority is risk_classifier
    # (resolve_risk), which the executor consults per invocation.
    risk_level = RiskLevel.MODIFIES_SYSTEM
    fallback_tool = None

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self._execute(arguments)

    def run_safe(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self._execute(arguments)

    @staticmethod
    def _execute(arguments: Dict[str, Any]) -> Dict[str, Any]:
        # --- Resolve command + environment from whichever mode was used ---
        preset_id = arguments.get("preset")
        try:
            if preset_id:
                command, environment, _interp = build_preset_command(
                    str(preset_id), arguments.get("params")
                )
            else:
                command = str(arguments.get("command", ""))
                environment = str(arguments.get("environment", "powershell")).lower()
        except UnknownPresetError as exc:
            available = ", ".join(sorted(COMMAND_PRESETS)[:20])
            return {
                "success": False,
                "output": "",
                "error": (
                    f"Unknown preset '{exc.args[0]}'. Known presets include: "
                    f"{available}{'...' if len(COMMAND_PRESETS) > 20 else ''}."
                ),
            }
        except MissingParameterError as exc:
            return {
                "success": False,
                "output": "",
                "error": f"Preset '{preset_id}' is missing required parameter: {exc.args[0]}.",
            }
        except ValueError as exc:
            return {"success": False, "output": "", "error": str(exc)}

        # --- Validate command ---
        if not command or not command.strip():
            return {
                "success": False,
                "output": "",
                "error": "Missing 'command' (or 'preset'). Provide something to execute.",
            }

        # --- Validate environment ---
        if environment not in VALID_ENVIRONMENTS:
            return {
                "success": False,
                "output": "",
                "error": (
                    f"Invalid environment '{environment}'. "
                    f"Must be one of: {', '.join(VALID_ENVIRONMENTS)}."
                ),
            }

        # --- Validate / coerce timeout ---
        timeout = arguments.get("timeout", 15)
        try:
            timeout = int(timeout)
            if timeout < 1:
                timeout = 15
        except (TypeError, ValueError):
            timeout = 15
        if timeout > 300:
            timeout = 300  # hard cap to prevent runaway processes

        # --- Delegate to the shared executor (risk was already gated upstream) ---
        result = execute_system_command(
            command=command,
            environment=environment,
            timeout=timeout,
        )

        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        returncode = result.get("returncode", -1)
        error = result.get("error", "")

        # A shell that reported a missing binary produced no evidence at all, so
        # it must not surface as an ordinary failed command with an empty result
        # -- that shape reads as "the check ran and found nothing". Carry the
        # absence through as a fact of its own.
        if result.get("status") == "tool_absent":
            binary = result.get("binary", "")
            return {
                "success": False,
                "status": "tool_absent",
                "output": stdout,
                "error": stderr or error or f"{binary}: not found",
                "binary": binary,
                "env": result.get("env", environment),
                "hint": result.get("hint", ""),
                "returncode": returncode,
                "environment": environment,
            }

        if error and returncode != 0:
            return {
                "success": False,
                "output": stdout,
                "error": error,
                "returncode": returncode,
                "environment": environment,
            }

        return {
            "success": returncode == 0,
            "output": stdout,
            "error": stderr or "",
            "returncode": returncode,
            "environment": environment,
        }


TOOL_CLASS = ShellExecTool
