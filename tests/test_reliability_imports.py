"""Reliability: the shipping entrypoints and core modules must import cleanly.

Agent 7 (QA/Reliability) baseline guard. A broken import is the single cheapest
way to turn a working build into a dead demo: nothing downstream runs, and the
failure surfaces as a blank window rather than an error. These tests pin that
every module on the startup path is importable in a plain interpreter with no
elevation, no driver, and no optional native dependency installed.

Scope note: this file deliberately asserts *importability and wiring only*. It
is NOT kernel, driver, or detection coverage, and must never be reported as
such.
"""

from __future__ import annotations

import importlib
import os
import sys

import pytest


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Modules on the startup path. Each must import with no optional native
# dependency present (no yara, no loaded minifilter, no admin rights).
CORE_MODULES = [
    "cyber_main",
    "cyber_agent",
    "key_manager",
    "cyber_os",
    "cyber_os.engine",
    "cyber_os.agent_runtime",
    "cyber_os.tool_orchestrator",
    "cyber_os.protection.scanner",
    "cyber_os.protection.store",
    "cyber_os.protection.service",
    "cyber_os.protection.models",
    "cyber_os.protection.rule_package",
    "cyber_os.protection.filter_client",
    "cyber_os.protection.filter_protocol",
    "cyber_os.protection.windows_service",
    "cyber_os.protection.windows_pipe_client",
    "ui.api_server",
]


@pytest.mark.parametrize("module_name", CORE_MODULES)
def test_core_module_imports_without_optional_native_dependencies(module_name: str) -> None:
    """Importing a startup-path module must not raise, even bare-metal."""
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # pragma: no cover - the failure *is* the signal
        pytest.fail(
            f"{module_name} failed to import: {type(exc).__name__}: {exc}\n"
            "A module on the startup path must import without optional native "
            "dependencies, elevation, or a loaded driver."
        )
    assert module is not None


def test_launcher_exposes_its_public_entrypoints() -> None:
    """cyber_main must keep the symbols the launcher and tests depend on."""
    cyber_main = importlib.import_module("cyber_main")
    for symbol in ("main", "build_parser", "_http_ready"):
        assert hasattr(cyber_main, symbol), f"cyber_main.{symbol} is missing"


def test_launcher_parser_builds_and_defaults_to_loopback() -> None:
    """Argument parsing must work offline and must not bind a public address."""
    cyber_main = importlib.import_module("cyber_main")
    args = cyber_main.build_parser().parse_args([])
    assert args.host == "127.0.0.1", (
        f"launcher default host is {args.host!r}; an endpoint protection agent "
        "must not default to a non-loopback bind"
    )


def test_api_server_exposes_a_fastapi_app_with_a_health_route() -> None:
    """The readiness probe the launcher waits on must actually be registered."""
    api_server = importlib.import_module("ui.api_server")
    app = getattr(api_server, "app", None)
    assert app is not None, "ui.api_server.app is missing"
    assert type(app).__name__ == "FastAPI", f"app is a {type(app).__name__}"

    routes = {getattr(route, "path", None) for route in app.routes}
    assert "/health" in routes, (
        "the launcher gates startup on GET /health (cyber_main.main); without "
        f"that route the readiness probe can never succeed. Routes: {sorted(p for p in routes if p)}"
    )


def test_health_route_answers_2xx_without_a_driver_or_elevation() -> None:
    """/health must respond even with no driver loaded and no admin rights."""
    from fastapi.testclient import TestClient

    api_server = importlib.import_module("ui.api_server")
    with TestClient(api_server.app) as client:
        response = client.get("/health")

    assert 200 <= response.status_code < 400, (
        f"/health returned {response.status_code}; the launcher's readiness "
        "gate accepts only 2xx/3xx, so this would hang startup for the full "
        "timeout on a machine without the driver installed"
    )
