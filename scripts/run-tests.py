#!/usr/bin/env python
"""scripts/run-tests.py

Unified test entrypoint for the SVS-Cyber / STAI suite (IDEAS #6).

WHY: the autonomous engineering routine (and humans) currently drive two separate
change-aware gates in two directories:

  * Python   -- python scripts/select-pytest.py   [--run]
  * Frontend -- node  scripts/test-frontend-changed.mjs

Juggling two runners is friction and a way to miss coverage: a run that only invokes
one of them silently skips the other surface. This wrapper runs BOTH and returns a
single aggregate exit status, so "did the tests pass?" is one command / one number.

It does not re-implement selection: it delegates to the two gates, which remain the
single source of truth for their own change -> test mappings.

USAGE:
  python scripts/run-tests.py                 # run both gates on the git working tree
  python scripts/run-tests.py --dry-run       # print both plans, run nothing
  python scripts/run-tests.py --python-only   # only the pytest gate
  python scripts/run-tests.py --frontend-only # only the frontend gate
  python scripts/run-tests.py --files a,b,c   # explicit changed-file list (both gates)
  python scripts/run-tests.py --since <ref>   # also include files changed vs <ref>
  python scripts/run-tests.py --selftest      # run the pure aggregation self-test
  python scripts/run-tests.py --help

EXIT CODES:
  0  every enabled gate passed (or nothing relevant changed)
  1  at least one gate failed
  2  setup/launch error (a gate could not be started, or bad arguments)

The aggregation logic is pure and unit-tested by scripts/run-tests.selftest.py
(no pytest, no jest, no git).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import List, NamedTuple, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent

PYTHON_GATE = "scripts/select-pytest.py"
FRONTEND_GATE = "scripts/test-frontend-changed.mjs"


class Gate(NamedTuple):
    """One change-aware gate to run, with the rendered command for display."""

    name: str
    argv: List[str]
    display: str


def build_gates(
    *,
    include_python: bool,
    include_frontend: bool,
    dry_run: bool,
    files: Optional[Sequence[str]] = None,
    since: Optional[str] = None,
    python_exe: str = "python",
    node_exe: str = "node",
) -> List[Gate]:
    """Return the gate commands to run, in order. Pure: no filesystem/process access.

    ``--files``/``--since`` are forwarded verbatim to both gates so a single changed
    set drives both selections and they can never disagree about the input.
    """
    shared: List[str] = []
    if files:
        shared += ["--files", ",".join(files)]
    if since:
        shared += ["--since", since]

    gates: List[Gate] = []
    if include_python:
        argv = [python_exe, PYTHON_GATE]
        if not dry_run:
            argv.append("--run")  # without --run the selector only prints a plan
        argv += shared
        gates.append(Gate("python", argv, " ".join(argv)))
    if include_frontend:
        argv = [node_exe, FRONTEND_GATE]
        if dry_run:
            argv.append("--dry-run")
        argv += shared
        gates.append(Gate("frontend", argv, " ".join(argv)))
    return gates


def aggregate(results: Sequence[tuple[str, int]]) -> int:
    """Collapse per-gate exit codes into one: 0 pass, 1 fail, 2 launch/setup error.

    Pure. A gate that could not be started (code 2) makes the whole run a setup
    error -- a runner that never ran must not be reported as a pass.
    """
    if not results:
        return 0
    codes = [code for _, code in results]
    if any(code == 2 for code in codes):
        return 2
    if any(code != 0 for code in codes):
        return 1
    return 0


def _run_gate(gate: Gate) -> int:
    print(f"\n===== [{gate.name}] {gate.display} =====", flush=True)
    try:
        completed = subprocess.run(gate.argv, cwd=str(REPO_ROOT))  # noqa: S603 - fixed internal commands
    except OSError as exc:  # gate could not be launched (missing interpreter, etc.)
        print(f"[run-tests] could not launch the {gate.name} gate: {exc}", file=sys.stderr)
        return 2
    return completed.returncode


def _run_selftest() -> int:
    selftest = Path(__file__).resolve().parent / "run-tests.selftest.py"
    return subprocess.run([sys.executable, str(selftest)]).returncode  # noqa: S603


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the Python and frontend change-aware test gates with one aggregate status.",
    )
    parser.add_argument("--dry-run", "--list", action="store_true", help="print both plans; run nothing")
    parser.add_argument("--python-only", action="store_true", help="only run the pytest gate")
    parser.add_argument("--frontend-only", action="store_true", help="only run the frontend gate")
    parser.add_argument("--files", help="explicit comma-separated changed files (repo-relative)")
    parser.add_argument("--since", help="also include files changed vs a git ref")
    parser.add_argument("--selftest", action="store_true", help="run the pure aggregation self-test and exit")
    opts = parser.parse_args(argv)

    if opts.selftest:
        return _run_selftest()

    if opts.python_only and opts.frontend_only:
        parser.error("--python-only and --frontend-only are mutually exclusive")

    include_python = not opts.frontend_only
    include_frontend = not opts.python_only

    files = [f.strip() for f in opts.files.split(",") if f.strip()] if opts.files else None

    gates = build_gates(
        include_python=include_python,
        include_frontend=include_frontend,
        dry_run=opts.dry_run,
        files=files,
        since=opts.since,
        python_exe=sys.executable,
    )
    if not gates:
        print("[run-tests] nothing to run.")
        return 0

    if opts.dry_run:
        print("[run-tests] dry run - planned gates:")
        for gate in gates:
            print(f"  [{gate.name}] {gate.display}")
        return 0

    results: List[tuple[str, int]] = []
    for gate in gates:
        results.append((gate.name, _run_gate(gate)))

    print("\n===== [run-tests] summary =====")
    for name, code in results:
        print(f"  {name:9s} -> {'PASS' if code == 0 else f'FAIL (exit {code})'}")
    overall = aggregate(results)
    print(f"  overall   -> {'PASS' if overall == 0 else f'FAIL (exit {overall})'}")
    return overall


if __name__ == "__main__":
    sys.exit(main())
