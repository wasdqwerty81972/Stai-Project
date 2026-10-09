#!/usr/bin/env python
"""scripts/select-pytest.selftest.py

Deterministic unit test for the pure mapping in select-pytest.py. Runs no pytest
and touches no git state -- it only asserts that each kind of changed file selects
the right test targets. Exits non-zero on any mismatch so the routine can treat it
as a fast regression check.

  python scripts/select-pytest.selftest.py

(The sibling module has a hyphen in its name, so it is loaded by path.)
"""

from __future__ import annotations

import importlib.util
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "select_pytest", os.path.join(_HERE, "select-pytest.py")
)
sel = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sel)

FULL_SUITE = sel.FULL_SUITE
targets_for_file = sel.targets_for_file
select_targets = sel.select_targets

failures = 0


def check(label, actual, expected):
    global failures
    ok = actual == expected
    if not ok:
        failures += 1
        print(f"FAIL: {label}\n   expected: {expected!r}\n   actual:   {actual!r}")
    else:
        print(f"ok: {label}")


# --- precise tier --------------------------------------------------------------
check("key_manager.py -> PROVIDER", targets_for_file("key_manager.py"), sel.PROVIDER)
check("cyber_main.py -> LAUNCHER", targets_for_file("cyber_main.py"), sel.LAUNCHER)
check("ui/api_server.py -> API_SERVER", targets_for_file("ui/api_server.py"), sel.API_SERVER)
check(
    "command_classifier.py -> CLASSIFIER",
    targets_for_file("cyber_os/policy/command_classifier.py"),
    sel.CLASSIFIER,
)
check("cyber_tools.py -> TOOLS", targets_for_file("cyber_tools.py"), sel.TOOLS)
check(
    "cyber_tools_toolresult.py -> TOOLS",
    targets_for_file("cyber_tools_toolresult.py"),
    sel.TOOLS,
)
check(
    "cyber_threat_intel.py -> TOOLS",
    targets_for_file("cyber_threat_intel.py"),
    sel.TOOLS,
)
check(
    "cyber_os/agent_runtime.py -> AGENT_LOOP",
    targets_for_file("cyber_os/agent_runtime.py"),
    sel.AGENT_LOOP,
)
check(
    "cyber_os/llm_json.py -> AGENT_LOOP",
    targets_for_file("cyber_os/llm_json.py"),
    sel.AGENT_LOOP,
)
check(
    "cyber_os/agent_bus.py -> AGENT_LOOP",
    targets_for_file("cyber_os/agent_bus.py"),
    sel.AGENT_LOOP,
)
check(
    "cyber_os/runtime/* -> AGENT_LOOP",
    targets_for_file("cyber_os/runtime/svs_agent.py"),
    sel.AGENT_LOOP,
)
check(
    "cyber_os/subagents/manager.py -> SUBAGENTS",
    targets_for_file("cyber_os/subagents/manager.py"),
    sel.SUBAGENTS,
)
check(
    "cyber_os/subagents/profiles.py -> SUBAGENTS",
    targets_for_file("cyber_os/subagents/profiles.py"),
    sel.SUBAGENTS,
)

# --- shared / core -> FULL_SUITE ----------------------------------------------
check(
    "contracts.py widens (NOT scoped to SUBAGENTS)",
    targets_for_file("cyber_os/subagents/contracts.py"),
    FULL_SUITE,
)
check("pytest.ini -> FULL_SUITE", targets_for_file("pytest.ini"), FULL_SUITE)
check("conftest.py -> FULL_SUITE", targets_for_file("conftest.py"), FULL_SUITE)
check("requirements.txt -> FULL_SUITE", targets_for_file("requirements.txt"), FULL_SUITE)
check("tests/__init__.py -> FULL_SUITE", targets_for_file("tests/__init__.py"), FULL_SUITE)

# --- unknown python -> FULL_SUITE (fail safe, never under-select) --------------
check(
    "unmapped cyber_os module -> FULL_SUITE",
    targets_for_file("cyber_os/correlation_engine.py"),
    FULL_SUITE,
)
check(
    "policy_engine.py (NOT the classifier) -> FULL_SUITE",
    targets_for_file("cyber_os/policy_engine.py"),
    FULL_SUITE,
)
check(
    "unmapped ui python -> FULL_SUITE",
    targets_for_file("ui/event_bus.py"),
    FULL_SUITE,
)
check(
    "brand-new root module -> FULL_SUITE",
    targets_for_file("some_new_module.py"),
    FULL_SUITE,
)

# --- a changed test file runs itself ------------------------------------------
check(
    "changed test file -> itself only",
    targets_for_file("tests/test_shell_exec.py"),
    ["tests/test_shell_exec.py"],
)

# --- ignore tier (returns None) -----------------------------------------------
check(
    "frontend tsx -> None (owned by the frontend gate)",
    targets_for_file("ui/hackerai/app/components/SvsCyberComposer.tsx"),
    None,
)
check(
    ".stai cache -> None",
    targets_for_file(".stai/svs-cyber/Default/Cache/Cache_Data/data_0"),
    None,
)
check(
    "reference tree .py -> None (not collected)",
    targets_for_file("HackerAI-Source/foo.py"),
    None,
)
check(
    "cyber_soc_engine .py -> None (not collected)",
    targets_for_file("cyber_soc_engine/engine.py"),
    None,
)
check("README.md -> None", targets_for_file("README.md"), None)
check("audit_log.json -> None", targets_for_file("audit_log.json"), None)
check(
    ".investigations json -> None",
    targets_for_file(".investigations/inv-20260928-abc.json"),
    None,
)
check("ideas note -> None", targets_for_file("ideas/shaan ideas-1"), None)
check(
    ".github workflow -> None",
    targets_for_file(".github/workflows/ecc-harness.yml"),
    None,
)

# --- normalization: Windows backslash paths -----------------------------------
check(
    "backslash path is normalized",
    targets_for_file("cyber_os\\agent_runtime.py"),
    sel.AGENT_LOOP,
)
check(
    "leading ./ is stripped",
    targets_for_file("./key_manager.py"),
    sel.PROVIDER,
)

# --- select_targets: full-suite dominance -------------------------------------
res = select_targets(["key_manager.py", "cyber_os/subagents/contracts.py"])
check("full-suite dominates mixed selection", res["full_suite"], True)
check(
    "contracts.py recorded in widened_by",
    "cyber_os/subagents/contracts.py" in res["widened_by"],
    True,
)

# --- select_targets: union + dedup + stable sort (no full suite) --------------
res = select_targets(["key_manager.py", "cyber_main.py"])
check("mixed precise selection does not widen", res["full_suite"], False)
check(
    "precise union is sorted + de-duplicated",
    res["targets"],
    sorted(set(sel.PROVIDER) | set(sel.LAUNCHER)),
)

# overlapping groups: SUBAGENTS and TOOLS both include test_tool_registry_consistency
res = select_targets(["cyber_os/subagents/manager.py", "cyber_tools.py"])
check(
    "overlapping groups de-duplicate the shared suite",
    res["targets"].count("tests/test_tool_registry_consistency.py"),
    1,
)
check("overlap selection does not widen", res["full_suite"], False)

# --- select_targets: ignore-only input ----------------------------------------
res = select_targets(
    [
        "README.md",
        ".stai/svs-cyber/Default/Cookies",
        "ui/hackerai/app/components/SvsCyberComposer.tsx",
        "audit_log.json",
    ]
)
check("ignore-only input matches nothing", res["matched"], [])
check("ignore-only input does not widen", res["full_suite"], False)
check("ignore-only input selects no targets", res["targets"], [])

if failures:
    print(f"\n{failures} assertion(s) failed.")
    sys.exit(1)
print("\nAll mapping assertions passed.")
