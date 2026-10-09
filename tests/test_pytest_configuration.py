"""Regression coverage for the repository's default pytest command."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Reference trees bundled under the repo root that must never be pulled into the
# project's own `tests/` collection. pytest.ini pins `testpaths = tests`; this is
# the belt-and-suspenders check that the pin holds and nothing re-widens it.
_OUT_OF_TREE_MARKERS = (
    "ECC-source",
    "HackerAI-Source",
    "dataxyz",
    "AEGIS_Test",
    "cyber_soc_engine",
)

# Collection imports the project's own modules, which is genuinely slow — a cold
# `import cyber_tools` runs ~30s on its own (heavy transitive deps), so a scoped
# collection measures ~45-60s and more under load. The invariant this test
# guards is *scope*, not speed, so the timeout is only a backstop against a true
# hang, not a performance budget. The slow import is tracked separately in
# .claude/IDEAS.md ("Lazy-import heavy deps in cyber_tools"); a tighter budget
# belongs in a dedicated perf test, not here, where it only produces flaky fails.
_COLLECTION_TIMEOUT_S = 240


def test_default_collection_is_limited_to_the_project_suite() -> None:
    """Bundled reference trees must not break the project's default test run."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=_COLLECTION_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            "Default `pytest --collect-only` did not finish within "
            f"{_COLLECTION_TIMEOUT_S}s. This is an import-performance problem "
            "(see .claude/IDEAS.md: slow cyber_tools import), not a scoping "
            "regression — confirm scope before raising the timeout."
        )

    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    # The project's own suite is collected ...
    assert "tests/test_agent_foundation.py" in result.stdout, combined
    # ... and the bundled reference trees are not dragged in with it.
    leaked = [marker for marker in _OUT_OF_TREE_MARKERS if marker in result.stdout]
    assert not leaked, (
        f"default collection leaked out-of-tree paths: {leaked}\n"
        f"{result.stdout[-2000:]}"
    )
