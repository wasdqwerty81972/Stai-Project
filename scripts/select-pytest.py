#!/usr/bin/env python
"""scripts/select-pytest.py

Change-aware pytest selector for the SVS-Cyber / STAI Python suite.

WHY: the autonomous engineering routine performs the "changed file -> affected
tests" mapping *by hand* every run (see .claude/ROUTINE_CHECKLIST.md, section
"Change -> test mapping"). Doing it by hand risks a run forgetting an affected
subsystem. This script encodes that same mapping so change-aware selection is
reproducible -- the Python mirror of scripts/test-frontend-changed.mjs (which
closed the same gap for the JS/TS frontend surface).

It is READ-ONLY by default: it prints the test targets it would run and the exact
pytest command. Pass --run to actually execute them.

DESIGN -- fail safe, never under-select:
  * A file that is clearly outside the collected `tests/` suite (the vendored
    reference trees, the ui/hackerai frontend, the .stai browser cache, docs,
    generated JSON logs) is IGNORED.
  * A file with a known, deliberate mapping selects just the affected suites.
  * ANY other Python file -- or a pytest-config / dependency-manifest change --
    widens to the FULL suite. Over-selecting is safe; under-selecting is not.

The mapping below is kept in lock-step with the "Change -> test mapping" table in
.claude/ROUTINE_CHECKLIST.md, which remains the single human-readable source of
truth. The mapping itself is pure and unit-tested by
scripts/select-pytest.selftest.py (no pytest, no git).

USAGE:
  python scripts/select-pytest.py                 # detect from git working tree, print plan
  python scripts/select-pytest.py --run           # ...and execute the selected pytest targets
  python scripts/select-pytest.py --since <ref>   # also include files changed vs <ref>
  python scripts/select-pytest.py --files a,b,c   # use an explicit changed-file list
  python scripts/select-pytest.py --help

EXIT CODES (default/plan mode): always 0 unless git/arg parsing fails (2).
EXIT CODES (--run): pytest's own exit code (0 = passed, non-zero = failed), or 0
when nothing relevant changed.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional, Sequence, Union

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Sentinel meaning "the change is broad enough that the whole suite must run".
FULL_SUITE = "__FULL_SUITE__"

# --- Test groups (every path verified to exist in tests/) --------------------
# These groups mirror .claude/ROUTINE_CHECKLIST.md "Change -> test mapping".
PROVIDER = [
    "tests/test_gemini_failover.py",
    "tests/test_provider_role_mapping.py",
    "tests/test_nemo_integration.py",
    "tests/test_ui_api_contract.py",
]
SUBAGENTS = [
    "tests/test_defensive_swarm.py",
    "tests/test_subagent_tool_contract.py",
    "tests/test_svs_subagents_integration.py",
    "tests/test_tool_registry_consistency.py",
]
TOOLS = [
    "tests/test_tool_registry_consistency.py",
    "tests/test_tool_recognition.py",
    "tests/test_tool_absence.py",
    "tests/test_shell_exec.py",
    "tests/test_execute_tool_success_propagation.py",
]
AGENT_LOOP = [
    "tests/test_agent_runtime_loop.py",
    "tests/test_tool_call_regressions.py",
    "tests/test_agent_loop_e2e.py",
    "tests/test_agent_foundation.py",
    "tests/test_agent_bus_compat.py",
]
LAUNCHER = [
    "tests/test_startup_readiness.py",
    "tests/test_cyber_main_launcher.py",
]
API_SERVER = [
    "tests/test_ui_api_contract.py",
    "tests/test_hackerai_integration.py",
]
CLASSIFIER = ["tests/test_command_classifier.py"]

# Path prefixes whose changes cannot affect the collected `tests/` suite.
# - .stai/            : Chromium browser-profile cache committed under the repo
# - ui/hackerai/      : the vendored frontend; owned by test-frontend-changed.mjs
# - reference trees   : excluded from collection (pytest.ini: testpaths = tests)
# - tooling/meta dirs : no import path into the suite
_IGNORE_PREFIXES = (
    ".stai/",
    "ui/hackerai/",
    "ECC-source/",
    "HackerAI-Source/",
    "dataxyz/",
    "AEGIS_Test/",
    "cyber_soc_engine/",
    ".git/",
    ".github/",
    ".claude/",
    ".investigations/",
    "ideas/",
    "node_modules/",
)

# Files that change test behavior globally -> always run the full suite.
_SHARED_CORE_FILES = frozenset(
    {
        "cyber_os/subagents/contracts.py",  # shared subagent contracts (named in checklist)
        "pytest.ini",
        "conftest.py",
        "tests/__init__.py",  # test-package init: shared across every test module
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
    }
)


def _normalize(path: str) -> str:
    """Repo-relative, forward-slash path with any leading ./ stripped."""
    p = path.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def targets_for_file(rel_path: str) -> Optional[Union[str, list]]:
    """Map one changed repo-relative path to the tests it should trigger.

    Returns:
      * None        -- the file cannot affect the collected Python suite (ignore)
      * FULL_SUITE  -- the change is broad/unknown; run everything (fail safe)
      * list[str]   -- the specific test files to run
    """
    p = _normalize(rel_path)
    if not p:
        return None

    # 1. Ignore files that cannot reach the collected tests/ suite.
    if p.startswith(_IGNORE_PREFIXES):
        return None
    if "/node_modules/" in p or "/__pycache__/" in p or p.endswith(".pyc"):
        return None

    # 2. Shared / core / config -> full suite (checked before narrower rules so a
    #    contracts.py change under cyber_os/subagents/ widens instead of scoping).
    if p in _SHARED_CORE_FILES:
        return FULL_SUITE
    base = p.rsplit("/", 1)[-1]
    if base.startswith("requirements") and base.endswith(".txt"):
        return FULL_SUITE

    # 3. Deliberate, narrow mappings (kept in sync with ROUTINE_CHECKLIST.md).
    if p == "key_manager.py":
        return list(PROVIDER)
    if p.startswith("cyber_os/subagents/"):
        return list(SUBAGENTS)
    # cyber_tools*.py and the threat-intel tool module -> tool/registry suites.
    if (base.startswith("cyber_tools") and base.endswith(".py")) or p == "cyber_threat_intel.py":
        return list(TOOLS)
    if p in ("cyber_os/agent_runtime.py", "cyber_os/llm_json.py", "cyber_os/agent_bus.py"):
        return list(AGENT_LOOP)
    if p.startswith("cyber_os/runtime/"):
        return list(AGENT_LOOP)
    if p == "cyber_main.py":
        return list(LAUNCHER)
    if p == "ui/api_server.py":
        return list(API_SERVER)
    if p == "cyber_os/policy/command_classifier.py":
        return list(CLASSIFIER)

    # 4. A changed test file runs itself (precise, no need to widen).
    if p.startswith("tests/") and base.startswith("test_") and p.endswith(".py"):
        return [p]

    # 5. Any other Python file, or a dependency manifest we did not special-case
    #    above, has uncertain blast radius -> run the full suite (never under-select).
    if p.endswith(".py"):
        return FULL_SUITE

    # 6. Everything else (docs, JSON logs, images, lockfiles) cannot affect tests.
    return None


def select_targets(files: Sequence[str]) -> dict:
    """Fold changed files into a selection.

    Returns a dict with:
      full_suite  -- bool, True when any file widened to the whole suite
      targets     -- sorted, de-duplicated list of specific test files
      matched     -- changed files that mapped to something (for logging)
      widened_by  -- changed files that forced the full suite (for logging)
    """
    full = False
    widened_by: list = []
    targets: set = set()
    matched: list = []
    for f in files:
        decision = targets_for_file(f)
        if decision is None:
            continue
        matched.append(_normalize(f))
        if decision is FULL_SUITE:
            full = True
            widened_by.append(_normalize(f))
            continue
        targets.update(decision)
    return {
        "full_suite": full,
        "targets": sorted(targets),
        "matched": matched,
        "widened_by": widened_by,
    }


def _git_lines(args: Sequence[str]) -> list:
    out = subprocess.check_output(["git", *args], cwd=REPO_ROOT, text=True)
    return [ln for ln in out.splitlines() if ln.strip()]


def git_changed_files(since: Optional[str]) -> list:
    """Changed files from the working tree (+ optional diff vs `since`).

    The .stai/ browser cache is filtered out here for a legible plan; the mapping
    ignores it regardless, so correctness never depends on this filter.
    """
    files: list = []
    if since:
        files += _git_lines(["diff", "--name-only", since])
    for line in _git_lines(["status", "--porcelain"]):
        p = line[3:]  # strip the "XY " status prefix
        if " -> " in p:  # rename: take the destination path
            p = p.split(" -> ", 1)[1]
        p = p.strip().strip('"')
        files.append(p)
    seen: set = set()
    uniq: list = []
    for f in files:
        n = _normalize(f)
        if n.startswith(".stai/") or n in seen:
            continue
        seen.add(n)
        uniq.append(f)
    return uniq


_HELP = """Change-aware pytest selector for the SVS-Cyber / STAI Python suite.

Prints the pytest targets affected by the changed files (read-only by default).

  --run             Execute the selected targets with `python -m pytest -q`.
  --since <ref>     Also include files changed vs a git ref (committed changes).
  --files a,b,c     Use an explicit comma-separated changed-file list (repo-relative).
  --help, -h        Show this help.

With no flags it reads the git working tree (staged + unstaged + untracked),
excluding the .stai/ cache, and prints the plan. The mapping is unit-tested by
scripts/select-pytest.selftest.py."""


def _parse_args(argv: Sequence[str]) -> dict:
    opts = {"run": False, "since": None, "files": None, "help": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--run":
            opts["run"] = True
        elif a in ("--help", "-h"):
            opts["help"] = True
        elif a == "--since":
            i += 1
            opts["since"] = argv[i] if i < len(argv) else None
        elif a.startswith("--since="):
            opts["since"] = a[len("--since="):]
        elif a == "--files":
            i += 1
            opts["files"] = [x for x in (argv[i] if i < len(argv) else "").split(",") if x]
        elif a.startswith("--files="):
            opts["files"] = [x for x in a[len("--files="):].split(",") if x]
        else:
            print(f"[pytest-gate] unknown argument: {a}", file=sys.stderr)
            sys.exit(2)
        i += 1
    return opts


def main(argv: Sequence[str]) -> int:
    opts = _parse_args(argv)
    if opts["help"]:
        print(_HELP)
        return 0

    if opts["files"] is not None:
        changed = opts["files"]
    else:
        try:
            changed = git_changed_files(opts["since"])
        except (subprocess.CalledProcessError, OSError) as err:
            print(f"[pytest-gate] could not determine changed files: {err}", file=sys.stderr)
            return 2

    sel = select_targets(changed)

    if not sel["matched"]:
        print("[pytest-gate] No Python-affecting files changed -- nothing to run.")
        return 0

    print("[pytest-gate] Changed files affecting the Python suite:")
    for f in sel["matched"]:
        print(f"  - {f}")

    if sel["full_suite"]:
        print("[pytest-gate] Shared/core/unknown change -> FULL suite.")
        for f in sel["widened_by"]:
            print(f"    (widened by: {f})")
        cmd = [sys.executable, "-m", "pytest", "-q", "tests"]
    else:
        print(f"[pytest-gate] Selected {len(sel['targets'])} test file(s):")
        for t in sel["targets"]:
            print(f"    {t}")
        cmd = [sys.executable, "-m", "pytest", "-q", *sel["targets"]]

    print(f"[pytest-gate] Command: {' '.join(cmd)}")

    if not opts["run"]:
        print("[pytest-gate] (plan only; pass --run to execute)")
        return 0

    return subprocess.call(cmd, cwd=REPO_ROOT)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
