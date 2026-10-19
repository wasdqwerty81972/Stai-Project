#!/usr/bin/env python
"""scripts/run-tests.selftest.py

Pure unit test for scripts/run-tests.py's aggregation + gate-building logic.

No pytest, no jest, no git: it imports the module and asserts on the pure
functions only, so it is fast and runs anywhere. Mirror of the existing
select-pytest.selftest.py / test-frontend-changed.selftest.mjs.

Run:  python scripts/run-tests.selftest.py   (exit 0 = all pass)
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load():
    spec = importlib.util.spec_from_file_location("run_tests", _HERE / "run-tests.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rt = _load()

_failures = []
_checks = 0


def check(label: str, got, want) -> None:
    global _checks
    _checks += 1
    if got != want:
        _failures.append(f"FAIL {label}\n     got:  {got!r}\n     want: {want!r}")


# --- aggregate ----------------------------------------------------------------
check("empty -> 0", rt.aggregate([]), 0)
check("single pass -> 0", rt.aggregate([("python", 0)]), 0)
check("both pass -> 0", rt.aggregate([("python", 0), ("frontend", 0)]), 0)
check("one fail -> 1", rt.aggregate([("python", 0), ("frontend", 1)]), 1)
check("first fail -> 1", rt.aggregate([("python", 1), ("frontend", 0)]), 1)
check("pytest exit 2 -> setup error 2", rt.aggregate([("python", 2), ("frontend", 0)]), 2)
check("launch failure 2 wins over fail 1", rt.aggregate([("python", 1), ("frontend", 2)]), 2)
check("any non-zero propagates", rt.aggregate([("python", 5)]), 1)


# --- build_gates: both gates, normal run --------------------------------------
gates = rt.build_gates(include_python=True, include_frontend=True, dry_run=False)
check("both -> 2 gates", len(gates), 2)
check("python gate name", gates[0].name, "python")
check("frontend gate name", gates[1].name, "frontend")
check("python gate adds --run when not dry-run", "--run" in gates[0].argv, True)
check("frontend gate no --dry-run when not dry-run", "--dry-run" in gates[1].argv, False)
check("python gate points at the selector", gates[0].argv[1], "scripts/select-pytest.py")
check("frontend gate points at the .mjs", gates[1].argv[1], "scripts/test-frontend-changed.mjs")

# --- build_gates: dry-run flips both sides ------------------------------------
dry = rt.build_gates(include_python=True, include_frontend=True, dry_run=True)
check("dry-run: python gate omits --run", "--run" in dry[0].argv, False)
check("dry-run: frontend gate gets --dry-run", "--dry-run" in dry[1].argv, True)

# --- build_gates: single-side selection --------------------------------------
only_py = rt.build_gates(include_python=True, include_frontend=False, dry_run=False)
check("python-only -> 1 gate", len(only_py), 1)
check("python-only is the python gate", only_py[0].name, "python")

only_fe = rt.build_gates(include_python=False, include_frontend=True, dry_run=False)
check("frontend-only -> 1 gate", len(only_fe), 1)
check("frontend-only is the frontend gate", only_fe[0].name, "frontend")

neither = rt.build_gates(include_python=False, include_frontend=False, dry_run=False)
check("neither -> 0 gates", len(neither), 0)

# --- build_gates: shared --files / --since forwarded to BOTH ------------------
shared = rt.build_gates(
    include_python=True,
    include_frontend=True,
    dry_run=False,
    files=["ui/api_server.py", "cyber_agent.py"],
    since="HEAD~3",
)
py, fe = shared
for label, gate in (("python", py), ("frontend", fe)):
    argv = gate.argv
    check(f"{label}: --files present", "--files" in argv, True)
    check(
        f"{label}: --files value joined",
        argv[argv.index("--files") + 1],
        "ui/api_server.py,cyber_agent.py",
    )
    check(f"{label}: --since present", "--since" in argv, True)
    check(f"{label}: --since value", argv[argv.index("--since") + 1], "HEAD~3")

# --- build_gates: custom interpreter names are honored ------------------------
custom = rt.build_gates(
    include_python=True,
    include_frontend=True,
    dry_run=False,
    python_exe="/usr/bin/python3",
    node_exe="/usr/bin/node",
)
check("custom python exe", custom[0].argv[0], "/usr/bin/python3")
check("custom node exe", custom[1].argv[0], "/usr/bin/node")

# --- report -------------------------------------------------------------------
print(f"run-tests.selftest: {_checks - len(_failures)}/{_checks} checks passed")
for failure in _failures:
    print(failure)
sys.exit(1 if _failures else 0)
