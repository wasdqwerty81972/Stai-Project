"""Regression coverage for the repository's default pytest command."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_default_collection_is_limited_to_the_project_suite() -> None:
    """Bundled reference trees must not break the project's default test run."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "tests/test_agent_foundation.py" in result.stdout
