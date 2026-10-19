"""Regression tests for root-level utility scripts collected by pytest."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_gemini_key_check_is_import_safe() -> None:
    """Pytest collection must not trigger live API-key validation."""
    result = subprocess.run(
        [sys.executable, "-c", "import test_gemini_keys"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
