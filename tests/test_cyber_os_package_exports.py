from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_python(source: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_importing_cyber_os_does_not_load_unrelated_agent_stack():
    result = _run_python(
        "import sys, cyber_os; "
        "assert 'cyber_os.engine' not in sys.modules; "
        "assert 'cyber_os.cyber_os_ai' not in sys.modules"
    )

    assert result.returncode == 0, result.stderr


def test_existing_package_exports_resolve_lazily():
    result = _run_python(
        "from cyber_os import CyberOSEngine, AgentEventBus, EventType; "
        "assert CyberOSEngine and AgentEventBus and EventType"
    )

    assert result.returncode == 0, result.stderr
