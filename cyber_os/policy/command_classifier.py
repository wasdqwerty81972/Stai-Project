"""
cyber_os/policy/command_classifier.py -- Risk classification for arbitrary shell
strings handed to a unified ``shell_exec`` tool.

WHY THIS EXISTS
---------------
Every CLI wrapper tool used to carry a fixed ``command_template`` plus a
hand-written ``risk_level``. ``nmap {target}`` could only ever be nmap, so a
per-tool ``READ_ONLY`` label was trustworthy and ``GuardrailManager`` could
auto-approve it unattended. Collapsing 59 wrappers into one
``shell_exec(command=...)`` deletes the template, and with it that guarantee.
This module is the replacement guarantee: it decides whether an *arbitrary,
attacker-influenceable* command string may carry a ``READ_ONLY`` label.

One misclassification means ``nmap 10.0.0.1; rm -rf /`` runs unattended while
the audit line reads ``auto_approved / read_only``. The module is therefore
written to fail toward "ask a human" in every ambiguous case.

TIER MAPPING
------------
``RiskTier`` member *names* are identical to ``cyber_tools.RiskLevel`` member
names (``READ_ONLY``, ``MODIFIES_SYSTEM``, ``DESTRUCTIVE``,
``KERNEL_INTERVENTION``) and ``RiskTier`` *values* are identical to
``RiskLevel`` values. ``CommandRisk.level`` is always a ``RiskLevel`` member
NAME as a plain ``str``. The caller maps it back with::

    from cyber_tools import RiskLevel
    risk_level = RiskLevel[result.level]          # by name
    # equivalently: RiskLevel(RiskTier[result.level].value)

This module deliberately does NOT import ``cyber_tools`` (at module scope or
anywhere else): that import pulls the whole tool catalog. Keeping the
classifier import-cheap and cycle-free is part of its job.

FOUR NON-NEGOTIABLE PRINCIPLES
------------------------------
1. Split first, classify EVERY segment, take ``max()``. Never classify only the
   prefix of a command line.
2. ``READ_ONLY`` is earned, never defaulted or inferred. Only an exact
   allowlist rule, matched on normalized ``argv[0]``, for an interpreter the
   rule declares, with every flag-shaped token accounted for, can produce it.
   An unknown binary floors at ``MODIFIES_SYSTEM``.
3. Unparseable escalates to ``DESTRUCTIVE`` (never the middle tier) with
   ``undecidable=True``. Failure to decompose is evidence of evasion.
4. A refuse-list hit pins the whole command to ``DESTRUCTIVE`` regardless of
   what the other segments look like.

PRIVILEGE NOTE (documented interpretation)
------------------------------------------
``requires_admin`` is the OR of (a) the matched rule's ``requires_admin``,
(b) target-derived admin (registry hives, System32, /etc, /boot, /dev, service
control verbs) and (c) the caller-supplied ``is_privileged``. Because
``is_privileged`` is one of the OR terms, the "``requires_admin`` and
``is_privileged`` -> raise one tier" rule reduces to: *while the agent is
already elevated, nothing is READ_ONLY.* That is the literal reading of the
specification and the fail-safe one -- an elevated agent has a larger blast
radius for every command -- so it is implemented as written rather than
softened. Levels are capped at ``KERNEL_INTERVENTION``.

LOADER FAILS CLOSED
-------------------
Missing file, unreadable file, malformed YAML, unknown ``level`` name, version
mismatch, or missing ``pyyaml`` all mean "no allowlist", which means every
command classifies at least ``MODIFIES_SYSTEM``. It never means "no rules, so
allow". ``ruleset_hash`` (sha256 of the raw bytes, ``"none"`` when absent) is
recorded on every result so that "why was this auto-approved?" is answerable
from the audit log alone.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

__all__ = [
    "RiskTier",
    "CommandRule",
    "Ruleset",
    "CommandRisk",
    "RULESET_VERSION",
    "MAX_NESTING_DEPTH",
    "DEFAULT_RULESET_PATH",
    "load_ruleset",
    "classify_command",
    "normalize_binary",
]


# ---------------------------------------------------------------------------
# Tiers
# ---------------------------------------------------------------------------

class RiskTier(str, Enum):
    """Names AND values mirror ``cyber_tools.RiskLevel`` exactly."""

    READ_ONLY = "read_only"
    MODIFIES_SYSTEM = "modifies_system"
    DESTRUCTIVE = "destructive"
    KERNEL_INTERVENTION = "kernel_intervention"


# Ascending blast radius. Index position is the tier rank.
TIER_ORDER: Tuple[str, ...] = (
    RiskTier.READ_ONLY.name,
    RiskTier.MODIFIES_SYSTEM.name,
    RiskTier.DESTRUCTIVE.name,
    RiskTier.KERNEL_INTERVENTION.name,
)
_TIER_RANK: Dict[str, int] = {name: i for i, name in enumerate(TIER_ORDER)}

READ_ONLY = RiskTier.READ_ONLY.name
MODIFIES_SYSTEM = RiskTier.MODIFIES_SYSTEM.name
DESTRUCTIVE = RiskTier.DESTRUCTIVE.name
KERNEL_INTERVENTION = RiskTier.KERNEL_INTERVENTION.name


def _rank(level: str) -> int:
    # An unrecognized level name is treated as maximally dangerous, never as safe.
    return _TIER_RANK.get(level, _TIER_RANK[KERNEL_INTERVENTION])


def _worst(*levels: str) -> str:
    best = READ_ONLY
    for level in levels:
        if level and _rank(level) > _rank(best):
            best = level
    return best


def _raise_one_tier(level: str) -> str:
    idx = min(_rank(level) + 1, len(TIER_ORDER) - 1)
    return TIER_ORDER[idx]


RULESET_VERSION = 1
MAX_NESTING_DEPTH = 3
DEFAULT_RULESET_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "command_rules.yaml")


# ---------------------------------------------------------------------------
# Interpreters
# ---------------------------------------------------------------------------

BASH = "bash"
CMD = "cmd"
POWERSHELL = "powershell"
SUPPORTED_INTERPRETERS = (BASH, CMD, POWERSHELL)

_INTERPRETER_ALIASES: Dict[str, str] = {
    "bash": BASH,
    "sh": BASH,
    "zsh": BASH,
    "dash": BASH,
    "ash": BASH,
    "wsl": BASH,
    "cross_platform": BASH,
    "cmd": CMD,
    "cmd.exe": CMD,
    "bat": CMD,
    "batch": CMD,
    "windows": CMD,
    "powershell": POWERSHELL,
    "powershell.exe": POWERSHELL,
    "pwsh": POWERSHELL,
    "pwsh.exe": POWERSHELL,
    "ps": POWERSHELL,
    "ps1": POWERSHELL,
}


def _canonical_interpreter(interpreter: Optional[str]) -> Optional[str]:
    if not isinstance(interpreter, str):
        return None
    return _INTERPRETER_ALIASES.get(interpreter.strip().casefold())


# ---------------------------------------------------------------------------
# Refuse-list data
# ---------------------------------------------------------------------------

# argv[0] values that evaluate an arbitrary string as code. `| sh`, `| iex`,
# `bash -c ...`, `cmd /c ...` and `powershell -enc ...` all land here.
_INTERPRETER_BINARIES = frozenset({
    "sh", "bash", "zsh", "dash", "ash", "ksh", "csh", "tcsh", "busybox",
    "cmd", "command", "powershell", "pwsh", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "msbuild", "installutil", "wmic",
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php",
    "lua", "tclsh", "osascript", "groovy", "jshell", "deno", "bun",
    "awk", "gawk", "nawk", "mawk",
    "eval", "iex", "invoke-expression", "invoke-command", "invoke-item",
    "start-process", "start-job", "start", "saps", "icm",
})

# argv[0] values that hand their tail to another program to execute.
_DELEGATING_BINARIES = frozenset({
    "xargs", "env", "nohup", "setsid", "nice", "stdbuf", "timeout", "watch",
    "ssh", "plink", "psexec", "paexec", "winrs", "at", "schtasks", "cron",
    "sudo", "doas", "su", "runas", "gsudo", "pkexec",
    "certutil", "bitsadmin", "forfiles", "find-exec",
})

# argv[0] values whose entire purpose is destruction / irreversible mutation.
_DESTRUCTIVE_BINARIES = frozenset({
    "rm", "rmdir", "rd", "del", "erase", "unlink", "shred", "srm", "wipe",
    "remove-item", "ri", "rmo", "remove-itemproperty", "clear-content",
    "format", "mkfs", "diskpart", "fdisk", "parted", "dd", "cipher",
    "vssadmin", "bcdedit", "bootrec", "reg", "regedit", "takeown", "icacls",
    "mv", "move", "ren", "rename", "rename-item", "move-item",
    "chmod", "chown", "attrib", "setfacl",
    "shutdown", "reboot", "halt", "poweroff", "restart-computer", "stop-computer",
    "killall", "pkill", "taskkill", "stop-process", "kill",
    "insmod", "rmmod", "modprobe", "kextload", "kextunload",
})

_KERNEL_BINARIES = frozenset({
    "insmod", "rmmod", "modprobe", "kextload", "kextunload", "bcdedit",
    "driverquery-load", "sysctl", "kldload", "kldunload",
})

# Downloaders: refused when their output is piped into an interpreter.
_DOWNLOADER_BINARIES = frozenset({
    "curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm",
    "bitsadmin", "certutil", "start-bitstransfer",
})

# Flags that hand a command string to a child process (argument-position
# execution). These are `eval` wearing a different hat.
_ARG_EXEC_FLAGS = frozenset({
    "-exec", "-execdir", "--exec", "-ok", "-okdir",
    "--to-command", "--use-compress-program", "-i", "--rsh-command",
    "--script", "--script-args", "--script-args-file", "--script-updatedb",
    "-scriptblock", "-command", "-encodedcommand", "-e", "-ec", "-enc",
    "-filter", "-preexec", "-pre", "-post",
    "/c", "/k", "/r",
    "-c",
})

# Flags in ``_ARG_EXEC_FLAGS`` that are only dangerous on specific binaries --
# too common elsewhere to refuse unconditionally.
_ARG_EXEC_FLAG_SCOPE: Dict[str, frozenset] = {
    "-c": frozenset(_INTERPRETER_BINARIES | {"git", "ssh", "docker"}),
    "-i": frozenset({"xargs", "rsync", "sed"}),
    "-e": frozenset(
        {"powershell", "pwsh", "sed", "perl", "python", "ruby", "node",
         "nc", "ncat", "netcat", "socat"}
    ),
    "-ec": frozenset({"powershell", "pwsh"}),
    "-enc": frozenset({"powershell", "pwsh"}),
    "-encodedcommand": frozenset({"powershell", "pwsh"}),
    "-command": frozenset({"powershell", "pwsh", "cmd"}),
    "-filter": frozenset({"wmic", "get-wmiobject"}),
    "/c": frozenset({"cmd", "command", "wmic", "certutil"}),
    "/k": frozenset({"cmd", "command"}),
    "/r": frozenset({"cmd", "command", "forfiles"}),
    "-pre": frozenset({"tar", "rsync"}),
    "-post": frozenset({"tar", "rsync"}),
    "-preexec": frozenset({"tar", "rsync"}),
}

# Casefolded fragments matched WITHIN a single argv token (never across the
# whole command string -- that is the substring-scanning anti-pattern this
# module exists to replace). Each of these encodes execution or decoding.
_ARG_EXEC_TOKEN_FRAGMENTS: Tuple[str, ...] = (
    "frombase64string",
    "core.pager=",
    "sshcommand=",
    "proxycommand=",
    "localcommand=",
    "permitlocalcommand",
    "-scriptblock",
    "system(",
    "exec:",
    "system:",
    "os.system",
    "subprocess.",
    "popen(",
    "invoke-expression",
    "downloadstring",
    "downloadfile",
    "|iex",
    "| iex",
    "--to-command",
)

_DECODE_FLAGS = frozenset({"-encodedcommand", "-enc", "-ec", "-e", "-encoded"})

_BASE64_DECODE_BINARIES = frozenset({"base64", "certutil", "openssl"})


# ---------------------------------------------------------------------------
# Redirection / output data
# ---------------------------------------------------------------------------

_REDIRECT_TOKEN_RE = re.compile(r"^(?:\d*&?>{1,2}|>{1,2}&?\d*)")

# `2>&1` / `>&2` / `2>&-` duplicate or close a file descriptor. They write no
# file, and they are ubiquitous on genuinely read-only diagnostics, so treating
# them as writes would destroy auto-approval for no security gain.
_FD_DUP_RE = re.compile(r"^\d*>&(?:\d+|-)$")

# A program name assembled at runtime (`$X`, `${IFS}`, backticks, `%WINDIR%`)
# cannot be matched against an allowlist at all -- there is nothing to match.
_RUNTIME_EXPANSION_RE = re.compile(r"[$`]|%[A-Za-z0-9_()]+%")

_OUTPUT_CMDLETS = frozenset({
    "out-file", "set-content", "add-content", "export-csv", "export-clixml",
    "tee", "tee-object", "new-item", "copy-item", "copy", "cp", "xcopy",
    "robocopy", "write-file",
})

_OUTPUT_FLAG_PREFIXES: Tuple[str, ...] = (
    "-on", "-oa", "-og", "-ox", "-os", "-oj", "-o",
    "--output", "-output", "-outfile", "--outfile", "-out", "--out",
    "--log", "--logfile", "--report", "--save",
)

# ``-Path``/``-FilePath`` are the standard parameter names of read-only
# PowerShell cmdlets too, so they only designate an output target when argv[0]
# is itself a writing cmdlet.
_CMDLET_TARGET_PARAMS = frozenset({"-path", "-filepath", "-literalpath", "-destination", "-outfile"})

# First path component (after the drive / mount root) that marks a protected
# location. Compared component-wise against an ``os.path.abspath`` result, so
# ``C:\Users\me\etc\notes`` is NOT protected while ``/etc/passwd`` is.
_PROTECTED_ROOT_COMPONENTS = frozenset({
    "windows", "winnt", "program files", "program files (x86)", "programdata",
    "system32", "syswow64",
    "etc", "boot", "dev", "sys", "proc",
})

_REGISTRY_PREFIXES: Tuple[str, ...] = (
    "hklm:", "hkcr:", "hku:", "hkcc:",
    "hkey_local_machine", "hkey_classes_root", "hkey_users",
    "registry::hkey_local_machine",
)

_ADMIN_BINARIES = frozenset({
    "sc", "systemctl", "service", "net", "netsh", "systemd-run",
    "stop-service", "start-service", "restart-service", "set-service",
    "new-service", "remove-service", "suspend-service", "resume-service",
    "sudo", "doas", "su", "runas", "pkexec", "gsudo", "mount", "umount",
    "useradd", "userdel", "usermod", "net-user", "new-localuser",
    "set-mppreference", "add-mppreference", "bcdedit", "vssadmin", "diskpart",
})


# ---------------------------------------------------------------------------
# Tokenizing (reuses cyber_os.approval_engine.tokenize_command)
# ---------------------------------------------------------------------------

_tokenizer = None


def _tokenize(text: str) -> List[str]:
    """Reuse ``ApprovalEngine.tokenize_command`` rather than writing a third
    tokenizer. Imported lazily so this module stays cheap and cycle-free; the
    ``shlex`` line is an identical-semantics emergency path used only if the
    import itself fails during a partial package initialization."""
    global _tokenizer
    if _tokenizer is None:
        try:
            from cyber_os.approval_engine import ApprovalEngine  # local import: see docstring

            _tokenizer = ApprovalEngine().tokenize_command
        except Exception:  # pragma: no cover - partial-init guard
            def _fallback(command: str) -> List[str]:
                try:
                    return shlex.split(command, posix=False)
                except Exception:
                    return command.strip().split()

            _tokenizer = _fallback
    try:
        return [t for t in _tokenizer(text) if t]
    except Exception:
        return [t for t in text.strip().split() if t]


_QUOTE_CHARS = "\"'"


def normalize_binary(token: str) -> str:
    """basename -> strip surrounding quotes -> strip ``.exe`` -> casefold.

    ``/bin/rm``, ``RM.EXE``, ``"rm"``, ``C:\\Windows\\System32\\rm.exe`` all
    normalize to ``rm``. Only ``.exe`` is stripped: stripping ``.bat``/``.cmd``
    would let ``nmap.bat`` inherit the ``nmap`` allowlist rule.
    """
    if not token:
        return ""
    raw = token.strip().strip(_QUOTE_CHARS).strip()
    if not raw:
        return ""
    # Handle both separators regardless of host platform.
    raw = raw.replace("\\", "/")
    raw = raw.rstrip("/")
    if not raw:
        return ""
    base = raw.rsplit("/", 1)[-1]
    base = base.strip().strip(_QUOTE_CHARS).strip()
    folded = base.casefold()
    if folded.endswith(".exe"):
        folded = folded[:-4]
    return folded


def _unquote(token: str) -> str:
    return token.strip().strip(_QUOTE_CHARS)


def _ascii_safe(text: str, limit: int = 160) -> str:
    """Reasons flow to a cp1252 stdout and may embed attacker-controlled bytes."""
    cleaned = []
    for ch in text:
        if ch in "\r\n\t":
            cleaned.append(" ")
        elif 32 <= ord(ch) < 127:
            cleaned.append(ch)
        else:
            cleaned.append("?")
    out = "".join(cleaned).strip()
    out = re.sub(r"\s+", " ", out)
    if len(out) > limit:
        out = out[: limit - 3] + "..."
    return out


# ---------------------------------------------------------------------------
# Ruleset
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CommandRule:
    id: str
    binary: str
    interpreters: Tuple[str, ...]
    allowed_flags: Tuple[str, ...]
    allowed_flag_prefixes: Tuple[str, ...]
    level: str
    requires_admin: bool = False
    reason: str = ""

    def permits_interpreter(self, interpreter: str) -> bool:
        return interpreter in self.interpreters

    def flag_ok(self, token: str) -> bool:
        folded = token.casefold()
        if folded in self.allowed_flags:
            return True
        for prefix in self.allowed_flag_prefixes:
            if prefix and folded.startswith(prefix):
                return True
        return False


@dataclass(frozen=True)
class Ruleset:
    version: int = 0
    rules: Tuple[CommandRule, ...] = ()
    ruleset_hash: str = "none"
    source_path: Optional[str] = None
    load_error: Optional[str] = None
    _index: Dict[str, Tuple[CommandRule, ...]] = field(default_factory=dict, compare=False, repr=False)

    @property
    def has_allowlist(self) -> bool:
        return bool(self.rules)

    def rules_for(self, binary: str) -> Tuple[CommandRule, ...]:
        return self._index.get(binary, ())


def _build_ruleset(
    version: int,
    rules: Sequence[CommandRule],
    ruleset_hash: str,
    source_path: Optional[str],
    load_error: Optional[str],
) -> Ruleset:
    index: Dict[str, List[CommandRule]] = {}
    for rule in rules:
        index.setdefault(rule.binary, []).append(rule)
    return Ruleset(
        version=version,
        rules=tuple(rules),
        ruleset_hash=ruleset_hash,
        source_path=source_path,
        load_error=load_error,
        _index={k: tuple(v) for k, v in index.items()},
    )


def _closed_ruleset(reason: str, ruleset_hash: str = "none", source_path: Optional[str] = None) -> Ruleset:
    """No allowlist. Every command then classifies at least MODIFIES_SYSTEM."""
    return _build_ruleset(0, (), ruleset_hash, source_path, reason)


def _norm_flag_list(raw, field_name: str) -> Tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        raise ValueError(f"{field_name} must be a list")
    out = []
    for item in raw:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} entries must be strings")
        item = item.strip()
        if item:
            out.append(item.casefold())
    return tuple(out)


def load_ruleset(path: Optional[str] = None) -> Ruleset:
    """Load the allowlist, failing closed on every error.

    Failing closed means "no allowlist", i.e. nothing can reach ``READ_ONLY``.
    It never means "no rules, so allow".
    """
    resolved = path or DEFAULT_RULESET_PATH

    try:
        with open(resolved, "rb") as handle:
            raw = handle.read()
    except FileNotFoundError:
        return _closed_ruleset(
            f"No command allowlist found at {_ascii_safe(str(resolved))}; nothing can be classified read-only.",
            source_path=resolved,
        )
    except OSError as exc:
        return _closed_ruleset(
            f"Command allowlist could not be read ({_ascii_safe(exc.__class__.__name__)}); "
            "nothing can be classified read-only.",
            source_path=resolved,
        )

    ruleset_hash = hashlib.sha256(raw).hexdigest()

    try:
        import yaml  # local import: optional dependency
    except Exception:
        return _closed_ruleset(
            "pyyaml is not installed, so the command allowlist could not be parsed; "
            "nothing can be classified read-only.",
            ruleset_hash=ruleset_hash,
            source_path=resolved,
        )

    try:
        data = yaml.safe_load(raw.decode("utf-8", errors="replace"))
    except Exception as exc:
        return _closed_ruleset(
            f"Command allowlist is malformed YAML ({_ascii_safe(exc.__class__.__name__)}); "
            "nothing can be classified read-only.",
            ruleset_hash=ruleset_hash,
            source_path=resolved,
        )

    if not isinstance(data, dict):
        return _closed_ruleset(
            "Command allowlist is not a YAML mapping; nothing can be classified read-only.",
            ruleset_hash=ruleset_hash,
            source_path=resolved,
        )

    version = data.get("version")
    if version != RULESET_VERSION:
        return _closed_ruleset(
            f"Command allowlist version {_ascii_safe(str(version))} is not the supported version "
            f"{RULESET_VERSION}; nothing can be classified read-only.",
            ruleset_hash=ruleset_hash,
            source_path=resolved,
        )

    raw_rules = data.get("rules")
    if raw_rules is None:
        raw_rules = []
    if not isinstance(raw_rules, list):
        return _closed_ruleset(
            "Command allowlist 'rules' is not a list; nothing can be classified read-only.",
            ruleset_hash=ruleset_hash,
            source_path=resolved,
        )

    rules: List[CommandRule] = []
    for position, entry in enumerate(raw_rules):
        try:
            if not isinstance(entry, dict):
                raise ValueError("rule entry is not a mapping")
            binary = normalize_binary(str(entry.get("binary", "")))
            if not binary:
                raise ValueError("rule has no binary")
            level_name = entry.get("level")
            if not isinstance(level_name, str) or level_name.strip().upper() not in _TIER_RANK:
                # An unknown level name invalidates the WHOLE ruleset: a typo
                # must not silently widen or narrow the allowlist.
                raise ValueError(f"unknown level name {level_name!r}")
            interpreters = []
            raw_interpreters = entry.get("interpreters") or []
            if not isinstance(raw_interpreters, (list, tuple)):
                raise ValueError("interpreters must be a list")
            for item in raw_interpreters:
                canonical = _canonical_interpreter(str(item))
                if canonical:
                    interpreters.append(canonical)
            rule_id = str(entry.get("id") or binary or f"rule-{position}")
            rules.append(
                CommandRule(
                    id=rule_id,
                    binary=binary,
                    interpreters=tuple(dict.fromkeys(interpreters)),
                    allowed_flags=_norm_flag_list(entry.get("allowed_flags"), "allowed_flags"),
                    allowed_flag_prefixes=_norm_flag_list(
                        entry.get("allowed_flag_prefixes"), "allowed_flag_prefixes"
                    ),
                    level=level_name.strip().upper(),
                    requires_admin=bool(entry.get("requires_admin", False)),
                    reason=_ascii_safe(str(entry.get("reason", "")), limit=240),
                )
            )
        except Exception as exc:
            return _closed_ruleset(
                f"Command allowlist rule #{position} is invalid ({_ascii_safe(str(exc))}); "
                "the whole allowlist is rejected and nothing can be classified read-only.",
                ruleset_hash=ruleset_hash,
                source_path=resolved,
            )

    return _build_ruleset(RULESET_VERSION, rules, ruleset_hash, resolved, None)


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CommandRisk:
    level: str
    requires_admin: bool
    reason: str
    matched_rules: List[str]
    segments: List[str]
    undecidable: bool
    confidence: str
    ruleset_hash: str

    @property
    def tier(self) -> RiskTier:
        return RiskTier[self.level]

    def is_auto_approvable(self) -> bool:
        return self.level == READ_ONLY and not self.undecidable and not self.requires_admin


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------

@dataclass
class _SplitContext:
    ok: bool = True
    depth_exceeded: bool = False
    failure: Optional[str] = None


_CMD_FOR_DO_RE = re.compile(r"(?i)(?:^|\s)do\s")


def _matching_close(text: str, start: int, open_ch: str, close_ch: str, interpreter: str) -> int:
    """Index just past the matching close, or -1 when unbalanced."""
    depth = 0
    quote = None
    i = start
    quote_chars = "\"'" if interpreter != CMD else "\""
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = None
            elif ch == "\\" and interpreter == BASH:
                i += 1
            i += 1
            continue
        if ch in quote_chars:
            quote = ch
            i += 1
            continue
        if ch == "\\" and interpreter == BASH:
            i += 2
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _split_segments(
    text: str,
    interpreter: str,
    depth: int = 0,
    out: Optional[List[str]] = None,
    ctx: Optional[_SplitContext] = None,
) -> Tuple[List[str], _SplitContext]:
    """Quote-aware decomposition into independently-executed segments.

    Separators per interpreter, plus command-substitution / script-block
    bodies, which each become their own segment.
    """
    if out is None:
        out = []
    if ctx is None:
        ctx = _SplitContext()

    if depth > MAX_NESTING_DEPTH:
        ctx.depth_exceeded = True
        return out, ctx

    quote_chars = "\"'" if interpreter != CMD else "\""
    # The separator set is deliberately the UNION across all three shells
    # rather than each shell's exact grammar. Over-splitting can only add
    # segments, and more segments can only raise the verdict via max(); under-
    # splitting is what produces a false READ_ONLY. Without this, `cmd` (where
    # `;` is an argument delimiter, not a separator) would classify
    # `nmap x ; reg add HKLM\Software\y` as READ_ONLY while the identical
    # string under bash is DESTRUCTIVE -- letting the caller's interpreter
    # label launder an injection.
    two_char_seps = ("&&", "||")
    one_char_seps = (";", "|", "\n", "\r")

    buf: List[str] = []
    quote: Optional[str] = None
    i = 0
    n = len(text)

    def flush() -> None:
        segment = "".join(buf).strip()
        buf.clear()
        if segment:
            out.append(segment)

    while i < n:
        ch = text[i]

        if quote:
            # Command substitution stays live inside double quotes in bash/PS.
            if quote == '"' and interpreter in (BASH, POWERSHELL) and text.startswith("$(", i):
                end = _matching_close(text, i + 1, "(", ")", interpreter)
                if end == -1:
                    ctx.ok = False
                    ctx.failure = "unbalanced command substitution"
                    return out, ctx
                _split_segments(text[i + 2 : end - 1], interpreter, depth + 1, out, ctx)
                buf.append(" ")
                i = end
                continue
            if quote == '"' and interpreter == BASH and ch == "`":
                end = text.find("`", i + 1)
                if end == -1:
                    ctx.ok = False
                    ctx.failure = "unterminated backtick substitution"
                    return out, ctx
                _split_segments(text[i + 1 : end], interpreter, depth + 1, out, ctx)
                buf.append(" ")
                i = end + 1
                continue
            if ch == "\\" and interpreter == BASH and i + 1 < n:
                buf.append(ch)
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            buf.append(ch)
            i += 1
            continue

        if ch == "\\" and interpreter == BASH:
            # Escaped separator: `find . -exec rm {} \;` is ONE segment.
            buf.append(ch)
            if i + 1 < n:
                buf.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue

        if ch in quote_chars:
            quote = ch
            buf.append(ch)
            i += 1
            continue

        if ch == "`" and interpreter in (BASH, POWERSHELL):
            if interpreter == BASH:
                end = text.find("`", i + 1)
                if end == -1:
                    ctx.ok = False
                    ctx.failure = "unterminated backtick substitution"
                    return out, ctx
                _split_segments(text[i + 1 : end], interpreter, depth + 1, out, ctx)
                buf.append(" ")
                i = end + 1
                continue
            # In PowerShell a backtick is an escape character.
            buf.append(ch)
            if i + 1 < n:
                buf.append(text[i + 1])
                i += 2
            else:
                i += 1
            continue

        if interpreter in (BASH, POWERSHELL) and text.startswith("$(", i):
            end = _matching_close(text, i + 1, "(", ")", interpreter)
            if end == -1:
                ctx.ok = False
                ctx.failure = "unbalanced command substitution"
                return out, ctx
            _split_segments(text[i + 2 : end - 1], interpreter, depth + 1, out, ctx)
            buf.append(" ")
            i = end
            continue

        if interpreter == BASH and (text.startswith("<(", i) or text.startswith(">(", i)):
            # Process substitution runs a command just like `$(...)` does.
            end = _matching_close(text, i + 1, "(", ")", interpreter)
            if end == -1:
                ctx.ok = False
                ctx.failure = "unbalanced process substitution"
                return out, ctx
            _split_segments(text[i + 2 : end - 1], interpreter, depth + 1, out, ctx)
            buf.append(" ")
            i = end
            continue

        if interpreter == POWERSHELL and ch == "{":
            # Covers `& { ... }` and `Invoke-Command -ScriptBlock { ... }`.
            end = _matching_close(text, i, "{", "}", interpreter)
            if end == -1:
                ctx.ok = False
                ctx.failure = "unbalanced script block"
                return out, ctx
            _split_segments(text[i + 1 : end - 1], interpreter, depth + 1, out, ctx)
            buf.append(" ")
            i = end
            continue

        two = text[i : i + 2]
        if two in two_char_seps:
            flush()
            i += 2
            continue

        if ch == "&":
            nxt = text[i + 1] if i + 1 < n else ""
            prev = buf[-1] if buf else ""
            if nxt == ">" or prev == ">" or (prev.isdigit() and len(buf) >= 2 and buf[-2] == ">"):
                buf.append(ch)
                i += 1
                continue
            flush()
            i += 1
            continue

        if ch in one_char_seps:
            flush()
            i += 1
            continue

        buf.append(ch)
        i += 1

    if quote is not None:
        ctx.ok = False
        ctx.failure = "unterminated quote"
        return out, ctx

    flush()

    if interpreter == CMD and depth == 0:
        out[:] = _expand_cmd_for_do(out)

    return out, ctx


def _expand_cmd_for_do(segments: Sequence[str]) -> List[str]:
    """`for /f %i in (...) do <cmd>` -- the body after `do` is its own segment."""
    expanded: List[str] = []
    for segment in segments:
        tokens = segment.split()
        if tokens and normalize_binary(tokens[0]) == "for":
            match = _CMD_FOR_DO_RE.search(segment)
            if match:
                head = segment[: match.start()].strip()
                body = segment[match.end() :].strip()
                if head:
                    expanded.append(head)
                if body:
                    expanded.append(body)
                continue
        expanded.append(segment)
    return expanded


# ---------------------------------------------------------------------------
# Path / target analysis
# ---------------------------------------------------------------------------

def _is_registry_path(token: str) -> bool:
    folded = _unquote(token).casefold()
    return any(folded.startswith(prefix) for prefix in _REGISTRY_PREFIXES)


def _path_components(token: str, cwd: Optional[str]) -> List[str]:
    raw = _unquote(token)
    if not raw:
        return []
    base = cwd or os.getcwd()
    try:
        absolute = os.path.abspath(os.path.join(base, raw))
    except Exception:
        return []
    _drive, remainder = os.path.splitdrive(absolute)
    parts = [p for p in re.split(r"[\\/]+", remainder) if p]
    return [p.casefold() for p in parts]


def _is_protected_target(token: str, cwd: Optional[str]) -> bool:
    """Drive-letter / mount-root comparison; never a substring scan."""
    if not token:
        return False
    if _is_registry_path(token):
        return True
    components = _path_components(token, cwd)
    if not components:
        return False
    if components[0] in _PROTECTED_ROOT_COMPONENTS:
        return True
    # A POSIX-absolute path typed under a Windows cwd keeps its own root.
    raw = _unquote(token).replace("\\", "/")
    if raw.startswith("/"):
        first = [p for p in raw.split("/") if p]
        if first and first[0].casefold() in _PROTECTED_ROOT_COMPONENTS:
            return True
    return False


def _target_requires_admin(token: str, cwd: Optional[str]) -> bool:
    if _is_registry_path(token):
        return True
    components = _path_components(token, cwd)
    if not components:
        return False
    return components[0] in {"windows", "winnt", "system32", "syswow64", "etc", "boot", "dev", "programdata"}


def _looks_like_flag(token: str, interpreter: str) -> bool:
    raw = _unquote(token)
    if not raw:
        return False
    if raw.startswith("-") and raw != "-" and not _REDIRECT_TOKEN_RE.match(raw):
        return True
    if interpreter == CMD and re.match(r"^/[A-Za-z][A-Za-z0-9]{0,9}(?::.*)?$", raw):
        return True
    return False


def _is_redirect_token(token: str) -> bool:
    raw = _unquote(token)
    if not raw:
        return False
    if _FD_DUP_RE.match(raw):
        return False
    return bool(_REDIRECT_TOKEN_RE.match(raw)) and (">" in raw)


def _output_flag_target(tokens: Sequence[str], index: int) -> Optional[str]:
    raw = _unquote(tokens[index])
    if "=" in raw:
        return raw.split("=", 1)[1]
    if index + 1 < len(tokens):
        candidate = _unquote(tokens[index + 1])
        if candidate and not candidate.startswith("-"):
            return candidate
    return None


def _is_output_flag(token: str) -> bool:
    raw = _unquote(token).casefold()
    if not raw.startswith("-"):
        return False
    head = raw.split("=", 1)[0]
    return head in _OUTPUT_FLAG_PREFIXES


# ---------------------------------------------------------------------------
# Segment classification
# ---------------------------------------------------------------------------

@dataclass
class _SegmentVerdict:
    # READ_ONLY is the neutral accumulator start, NOT a default answer: every
    # path through the allowlist section either validates a rule or applies a
    # floor, and the command-level check refuses to emit READ_ONLY unless a
    # rule came back clean.
    level: str = READ_ONLY
    requires_admin: bool = False
    rule_id: Optional[str] = None
    reason: str = ""
    refused: bool = False
    undecidable: bool = False
    rule_clean: bool = False
    decode_note: Optional[str] = None
    decoded_payload: Optional[str] = None


def _refuse(verdict: _SegmentVerdict, reason: str) -> _SegmentVerdict:
    verdict.level = _worst(verdict.level, DESTRUCTIVE)
    verdict.refused = True
    verdict.rule_clean = False
    if reason and reason not in verdict.reason:
        verdict.reason = f"{verdict.reason} {reason}".strip() if verdict.reason else reason
    return verdict


def _try_decode(blob: str) -> Tuple[Optional[str], str]:
    """One decode pass, purely to enrich the operator card.

    Returns ``(decoded_text_or_None, note)``. A decode pass can never yield
    ``READ_ONLY``; callers floor it at ``MODIFIES_SYSTEM``.
    """
    candidate = _unquote(blob).strip()
    if not candidate:
        return None, "encoded payload was empty and could not be decoded"
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None, "encoded payload could NOT be decoded (not valid base64)"
    if not raw:
        return None, "encoded payload decoded to zero bytes and could not be read"
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if text.count("\x00") > len(text) // 4:
            continue
        return text, "encoded payload decoded"
    return None, "encoded payload COULD NOT be decoded to text (unknown encoding)"


def _classify_segment(
    segment: str,
    interpreter: str,
    ruleset: Ruleset,
    cwd: Optional[str],
) -> _SegmentVerdict:
    verdict = _SegmentVerdict()
    tokens = _tokenize(segment)
    if not tokens:
        verdict.level = MODIFIES_SYSTEM
        verdict.reason = "empty segment could not be resolved to a program"
        return verdict

    binary = normalize_binary(tokens[0])
    if not binary:
        return _refuse(verdict, "segment has no resolvable program name")
    if _RUNTIME_EXPANSION_RE.search(_unquote(tokens[0])):
        _refuse(
            verdict,
            "the program name is assembled at runtime from a variable, so no allowlist rule "
            "can describe what would actually run",
        )
    rest = tokens[1:]
    folded_rest = [_unquote(t).casefold() for t in rest]

    # --- Refuse list (pins the whole command to DESTRUCTIVE) ---------------
    if binary in _INTERPRETER_BINARIES:
        _refuse(
            verdict,
            f"'{_ascii_safe(binary)}' evaluates an arbitrary string as code, so its effect "
            "cannot be reviewed before it runs",
        )
    if binary in _DELEGATING_BINARIES:
        _refuse(
            verdict,
            f"'{_ascii_safe(binary)}' hands its arguments to another program to execute",
        )
    if binary in _DESTRUCTIVE_BINARIES:
        verdict.level = _worst(verdict.level, DESTRUCTIVE)
        verdict.rule_clean = False
        note = f"'{_ascii_safe(binary)}' deletes or irreversibly changes data"
        verdict.reason = f"{verdict.reason} {note}".strip() if verdict.reason else note
    if binary in _KERNEL_BINARIES:
        verdict.level = _worst(verdict.level, KERNEL_INTERVENTION)
        verdict.requires_admin = True
        note = f"'{_ascii_safe(binary)}' loads or alters kernel-level components"
        verdict.reason = f"{verdict.reason} {note}".strip() if verdict.reason else note

    for position, token in enumerate(rest):
        folded = folded_rest[position]
        head = folded.split("=", 1)[0]
        if head in _ARG_EXEC_FLAGS:
            scope = _ARG_EXEC_FLAG_SCOPE.get(head)
            if scope is None or binary in scope:
                _refuse(
                    verdict,
                    f"'{_ascii_safe(head)}' passes a command to be executed in argument position",
                )
        for fragment in _ARG_EXEC_TOKEN_FRAGMENTS:
            if fragment in folded:
                _refuse(
                    verdict,
                    f"argument contains the execution or decoding construct "
                    f"'{_ascii_safe(fragment)}'",
                )
                break

    if binary in _BASE64_DECODE_BINARIES:
        for folded in folded_rest:
            if folded.split("=", 1)[0] in {"-decode", "-d", "--decode", "-decodehex", "-base64", "base64"}:
                _refuse(
                    verdict,
                    f"'{_ascii_safe(binary)}' is being used to decode a payload before executing it",
                )
                break

    # Encoded-command decode pass (reason enrichment only, floored below).
    for position, folded in enumerate(folded_rest):
        head = folded.split("=", 1)[0]
        if head in _DECODE_FLAGS and binary in {"powershell", "pwsh", "base64", "certutil"}:
            blob = None
            if "=" in folded:
                blob = _unquote(rest[position]).split("=", 1)[1]
            elif position + 1 < len(rest):
                blob = rest[position + 1]
            decoded, note = _try_decode(blob or "")
            verdict.decode_note = note
            if decoded is None:
                verdict.undecidable = True
                _refuse(verdict, note)
            else:
                verdict.decoded_payload = decoded
                _refuse(verdict, note)
            break

    # --- Allowlist ---------------------------------------------------------
    candidates = ruleset.rules_for(binary)
    if not candidates:
        if not ruleset.has_allowlist:
            detail = ruleset.load_error or "no command allowlist is loaded"
            verdict.level = _worst(verdict.level, MODIFIES_SYSTEM)
            note = _ascii_safe(detail, limit=240)
        else:
            verdict.level = _worst(verdict.level, MODIFIES_SYSTEM)
            note = (
                f"'{_ascii_safe(binary)}' is not on the read-only allowlist, so its effect on the "
                "host is unknown"
            )
        verdict.reason = f"{verdict.reason} {note}".strip() if verdict.reason else note
    else:
        interpreter_ok = [r for r in candidates if r.permits_interpreter(interpreter)]
        if not interpreter_ok:
            verdict.level = _worst(verdict.level, MODIFIES_SYSTEM)
            note = (
                f"the allowlist rule for '{_ascii_safe(binary)}' is not authorized for the "
                f"{_ascii_safe(interpreter)} interpreter"
            )
            verdict.reason = f"{verdict.reason} {note}".strip() if verdict.reason else note
        else:
            validated: List[CommandRule] = []
            offending: List[str] = []
            for rule in interpreter_ok:
                bad = [
                    _unquote(t)
                    for t in rest
                    if _looks_like_flag(t, interpreter) and not rule.flag_ok(_unquote(t))
                ]
                if bad:
                    offending.extend(bad)
                else:
                    validated.append(rule)
            if validated:
                # Conservative when several rules match the same binary.
                chosen = max(validated, key=lambda r: _rank(r.level))
                verdict.rule_id = chosen.id
                verdict.requires_admin = verdict.requires_admin or chosen.requires_admin
                verdict.level = _worst(verdict.level, chosen.level)
                if not verdict.refused and verdict.level == chosen.level:
                    verdict.rule_clean = True
                note = chosen.reason or f"matched allowlist rule '{_ascii_safe(chosen.id)}'"
                verdict.reason = f"{verdict.reason} {note}".strip() if verdict.reason else note
            else:
                verdict.level = _worst(verdict.level, MODIFIES_SYSTEM)
                unique = ", ".join(dict.fromkeys(_ascii_safe(f) for f in offending)) or "unknown flag"
                note = (
                    f"'{_ascii_safe(binary)}' is allowlisted but carries flags the rule does not "
                    f"cover ({unique}), which can redirect it into other programs or files"
                )
                verdict.reason = f"{verdict.reason} {note}".strip() if verdict.reason else note

    # --- Redirection / output targets -------------------------------------
    targets: List[str] = []
    for position, token in enumerate(rest):
        raw = _unquote(token)
        if _is_redirect_token(token):
            trailing = _REDIRECT_TOKEN_RE.sub("", raw, count=1).strip()
            if trailing:
                targets.append(trailing)
            elif position + 1 < len(rest):
                targets.append(_unquote(rest[position + 1]))
            else:
                targets.append("")
        elif _is_output_flag(token):
            target = _output_flag_target(rest, position)
            targets.append(target or "")

    if binary in _OUTPUT_CMDLETS:
        verdict.level = _worst(verdict.level, MODIFIES_SYSTEM)
        verdict.rule_clean = False
        note = f"'{_ascii_safe(binary)}' writes to a file"
        verdict.reason = f"{verdict.reason} {note}".strip() if verdict.reason else note
        named_target = None
        for position, token in enumerate(rest):
            if folded_rest[position].split("=", 1)[0] in _CMDLET_TARGET_PARAMS:
                named_target = _output_flag_target(rest, position)
                break
        if named_target:
            targets.append(named_target)
        else:
            for token in rest:
                if not _looks_like_flag(token, interpreter):
                    targets.append(_unquote(token))
                    break

    if targets:
        verdict.level = _worst(verdict.level, MODIFIES_SYSTEM)
        verdict.rule_clean = False
        note = "writes output to a file, so it changes the host"
        verdict.reason = f"{verdict.reason} {note}".strip() if verdict.reason else note
        for target in targets:
            if target and _is_protected_target(target, cwd):
                verdict.level = _worst(verdict.level, DESTRUCTIVE)
                verdict.requires_admin = True
                protected_note = (
                    f"output target '{_ascii_safe(target, limit=80)}' is inside a protected "
                    "system location"
                )
                verdict.reason = f"{verdict.reason} {protected_note}".strip()
            elif target and _target_requires_admin(target, cwd):
                verdict.requires_admin = True

    # --- Admin-derived ----------------------------------------------------
    if binary in _ADMIN_BINARIES:
        verdict.requires_admin = True
        verdict.level = _worst(verdict.level, MODIFIES_SYSTEM)
        verdict.rule_clean = False
        note = f"'{_ascii_safe(binary)}' controls services or accounts and needs administrator rights"
        verdict.reason = f"{verdict.reason} {note}".strip() if verdict.reason else note

    for token in rest:
        if _target_requires_admin(token, cwd):
            verdict.requires_admin = True
            break

    if verdict.refused:
        verdict.rule_clean = False

    return verdict


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _undecidable_result(
    reason: str,
    ruleset_hash: str,
    segments: Optional[List[str]] = None,
    requires_admin: bool = False,
) -> CommandRisk:
    return CommandRisk(
        level=DESTRUCTIVE,
        requires_admin=requires_admin,
        reason=_ascii_safe(reason, limit=400),
        matched_rules=[],
        segments=list(segments or []),
        undecidable=True,
        confidence="none",
        ruleset_hash=ruleset_hash,
    )


def classify_command(
    command: str,
    interpreter: str,
    *,
    ruleset: Optional[Ruleset] = None,
    cwd: Optional[str] = None,
    is_privileged: bool = False,
) -> CommandRisk:
    """Classify an arbitrary command string for the given interpreter.

    Never raises: any internal failure returns ``DESTRUCTIVE`` +
    ``undecidable=True``, because a classifier that cannot answer must not
    answer permissively.
    """
    active = ruleset
    ruleset_hash = "none"
    try:
        if active is None:
            active = load_ruleset()
        ruleset_hash = active.ruleset_hash or "none"
        return _classify(command, interpreter, active, cwd, is_privileged)
    except Exception as exc:  # fail closed, loudly
        return _undecidable_result(
            "The command could not be classified because the classifier itself failed "
            f"({_ascii_safe(exc.__class__.__name__)}); human review is required.",
            ruleset_hash,
        )


def _classify(
    command: str,
    interpreter: str,
    ruleset: Ruleset,
    cwd: Optional[str],
    is_privileged: bool,
) -> CommandRisk:
    ruleset_hash = ruleset.ruleset_hash or "none"

    if not isinstance(command, str) or not command.strip():
        return _undecidable_result(
            "An empty command string cannot be classified; human review is required.",
            ruleset_hash,
            requires_admin=is_privileged,
        )

    canonical_interpreter = _canonical_interpreter(interpreter)
    if canonical_interpreter is None:
        return _undecidable_result(
            f"Interpreter '{_ascii_safe(str(interpreter), limit=40)}' is not one of "
            f"{', '.join(SUPPORTED_INTERPRETERS)}, so the command cannot be decomposed; "
            "human review is required.",
            ruleset_hash,
            requires_admin=is_privileged,
        )

    if "\x00" in command:
        return _undecidable_result(
            "The command contains a NUL byte, which is an evasion attempt rather than a "
            "legitimate command; human review is required.",
            ruleset_hash,
            requires_admin=is_privileged,
        )

    segments, ctx = _split_segments(command, canonical_interpreter)

    if ctx.depth_exceeded:
        return _undecidable_result(
            f"The command nests command substitutions or script blocks deeper than "
            f"{MAX_NESTING_DEPTH} levels, which hides what actually executes; "
            "human review is required.",
            ruleset_hash,
            segments=segments,
            requires_admin=is_privileged,
        )

    if not ctx.ok:
        return _undecidable_result(
            f"The command could not be decomposed ({_ascii_safe(ctx.failure or 'parse failure')}), "
            "so the programs it would run are unknown; human review is required.",
            ruleset_hash,
            segments=segments,
            requires_admin=is_privileged,
        )

    if not segments:
        return _undecidable_result(
            "No executable segment could be recovered from the command; human review is required.",
            ruleset_hash,
            requires_admin=is_privileged,
        )

    level = READ_ONLY
    requires_admin = bool(is_privileged)
    refused = False
    undecidable = False
    matched_rules: List[str] = []
    reasons: List[str] = []
    all_rule_clean = True
    decoded_payloads: List[str] = []

    for segment in segments:
        verdict = _classify_segment(segment, canonical_interpreter, ruleset, cwd)
        level = _worst(level, verdict.level)
        requires_admin = requires_admin or verdict.requires_admin
        refused = refused or verdict.refused
        undecidable = undecidable or verdict.undecidable
        if verdict.rule_id and verdict.rule_id not in matched_rules:
            matched_rules.append(verdict.rule_id)
        if not verdict.rule_clean:
            all_rule_clean = False
        if verdict.reason:
            reasons.append(verdict.reason)
        if verdict.decoded_payload:
            decoded_payloads.append(verdict.decoded_payload)

    # Refuse-list hit pins the whole command regardless of the other segments.
    if refused:
        level = _worst(level, DESTRUCTIVE)
        all_rule_clean = False

    # One decode pass is for the operator card only. It is floored at
    # MODIFIES_SYSTEM and can never lower the verdict.
    for payload in decoded_payloads:
        inner_segments, inner_ctx = _split_segments(payload, canonical_interpreter)
        if not inner_ctx.ok or inner_ctx.depth_exceeded:
            level = _worst(level, DESTRUCTIVE)
            undecidable = True
            reasons.append("the decoded payload could not itself be decomposed")
            continue
        inner_level = MODIFIES_SYSTEM  # floor: a decode pass never yields READ_ONLY
        for inner in inner_segments:
            inner_verdict = _classify_segment(inner, canonical_interpreter, ruleset, cwd)
            inner_level = _worst(inner_level, inner_verdict.level)
            requires_admin = requires_admin or inner_verdict.requires_admin
        level = _worst(level, inner_level)
        reasons.append(
            f"decoded payload is '{_ascii_safe(payload, limit=120)}' which classifies as "
            f"{inner_level} at best"
        )

    if undecidable:
        level = _worst(level, DESTRUCTIVE)

    # Privilege escalation. See the module docstring: is_privileged is one of
    # the OR terms of requires_admin, so an elevated agent raises every tier.
    if requires_admin and is_privileged:
        before = level
        level = _raise_one_tier(level)
        if level != before:
            reasons.append(
                "raised one tier because the agent is already running elevated, which widens "
                "the blast radius of this command"
            )
        else:
            reasons.append(
                "already at the highest tier, so the elevated-agent escalation could not raise it further"
            )

    if level == READ_ONLY and (refused or undecidable or not all_rule_clean):
        # Belt and braces: READ_ONLY must be impossible unless every segment
        # came back clean from an allowlist rule.
        level = MODIFIES_SYSTEM
        reasons.append("read-only could not be established for every part of the command")

    if level == READ_ONLY:
        confidence = "rule"
    elif not ruleset.has_allowlist:
        confidence = "none"
    elif all_rule_clean and matched_rules:
        confidence = "rule"
    elif matched_rules:
        confidence = "inferred"
    else:
        confidence = "inferred"

    if not ruleset.has_allowlist and not matched_rules:
        confidence = "none"

    reason = _ascii_safe("; ".join(dict.fromkeys(r for r in reasons if r)), limit=800)
    if not reason:
        reason = "no risk-relevant construct was identified, so the command is held for review"

    return CommandRisk(
        level=level,
        requires_admin=requires_admin,
        reason=reason,
        matched_rules=matched_rules,
        segments=list(segments),
        undecidable=undecidable,
        confidence=confidence,
        ruleset_hash=ruleset_hash,
    )
