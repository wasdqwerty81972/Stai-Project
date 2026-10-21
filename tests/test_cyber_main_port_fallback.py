from __future__ import annotations

import socket
import json
import shutil
import subprocess
from pathlib import Path

import pytest

import cyber_main
from ui.api_server import communications_allowed_origins


def test_port_candidates_include_preferred_and_five_fallbacks():
    assert cyber_main.port_candidates(6764) == [6764, 6765, 6766, 6767, 6768, 6769]


def test_resolve_port_reuses_a_healthy_preferred_service():
    seen: list[int] = []

    selected = cyber_main.resolve_service_port(
        "API",
        6764,
        is_ready=lambda port: port == 6764,
        can_bind=lambda port: seen.append(port) or True,
    )

    assert selected == 6764
    assert seen == []


def test_resolve_port_falls_back_when_preferred_port_is_occupied():
    selected = cyber_main.resolve_service_port(
        "API",
        6764,
        is_ready=lambda _port: False,
        can_bind=lambda port: port != 6764,
    )

    assert selected == 6765


def test_service_port_planning_skips_ports_reserved_for_other_services():
    selected = cyber_main.resolve_service_port(
        "dashboard", 3000,
        is_ready=lambda _port: True,
        can_bind=lambda _port: True,
        reserved_ports=(3000,),
    )
    assert selected == 3001


def test_agent_port_planning_does_not_reuse_api_or_dashboard_port():
    port, url = cyber_main.resolve_agent_workspace_port(
        3000,
        is_ready=lambda _port: False,
        can_bind=lambda _port: True,
        reserved_ports=(3000, 3001),
    )
    assert (port, url) == (3002, "http://127.0.0.1:3002")


def test_resolve_port_skips_a_real_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        occupied_port = listener.getsockname()[1]

        selected = cyber_main.resolve_service_port(
            "test service",
            occupied_port,
            is_ready=lambda _port: False,
        )

    assert selected in cyber_main.port_candidates(occupied_port)
    assert selected != occupied_port


def test_resolve_port_fails_with_attempted_ports_when_all_are_occupied():
    with pytest.raises(RuntimeError, match=r"API.*6764.*6769"):
        cyber_main.resolve_service_port(
            "API",
            6764,
            is_ready=lambda _port: False,
            can_bind=lambda _port: False,
        )


def test_port_candidates_stop_at_valid_tcp_port_range():
    assert cyber_main.port_candidates(65534) == [65534, 65535]


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_port_candidates_reject_invalid_preferred_ports(port: int):
    with pytest.raises(ValueError, match="between 1 and 65535"):
        cyber_main.port_candidates(port)


def test_cors_allowlist_includes_only_valid_selected_loopback_ports():
    origins = communications_allowed_origins("1423,3002,0,70000,invalid")

    assert "http://127.0.0.1:1423" in origins
    assert "http://localhost:1423" in origins
    assert "http://127.0.0.1:3002" in origins
    assert "http://localhost:3002" in origins
    assert "http://127.0.0.1:70000" not in origins


def test_selected_ports_are_propagated_to_child_processes():
    environment = cyber_main.build_child_environment(
        {"PATH": "path"},
        host="127.0.0.1",
        api_port=6766,
        frontend_port=1423,
        agent_port=3002,
    )

    assert environment["NEXT_PUBLIC_BACKEND_ORIGIN"] == "http://127.0.0.1:6766"
    assert environment["STAI_API_ORIGIN"] == "http://127.0.0.1:6766"
    assert environment["STAI_API_PORT"] == "6766"
    assert environment["STAI_FRONTEND_PORT"] == "1423"
    assert environment["VITE_STAI_TAURI_DEV_PORT"] == "1423"
    assert environment["STAI_AGENT_PORT"] == "3002"
    assert environment["STAI_CORS_ALLOWED_PORTS"] == "1423,3002"


def test_unstarted_agent_gets_a_readiness_url_for_its_selected_port():
    port, url = cyber_main.resolve_agent_workspace_port(
        3000,
        is_ready=lambda _port: False,
        can_bind=lambda _port: True,
    )

    assert port == 3000
    assert url == "http://127.0.0.1:3000"


def test_agent_readiness_url_uses_the_selected_fallback_port():
    port, url = cyber_main.resolve_agent_workspace_port(
        3000,
        is_ready=lambda _port: False,
        can_bind=lambda candidate: candidate != 3000,
    )

    assert port == 3001
    assert url == "http://127.0.0.1:3001"


@pytest.mark.parametrize(
    "task,frontend_port,expected_port", [("build", "", None), ("dev", "1423", 1423), ("dev", "", 1422)]
)
def test_desktop_launcher_propagates_fallbacks_and_bounded_csp(task, frontend_port, expected_port):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the desktop launcher")
    desktop = Path(__file__).resolve().parents[1] / "ui/hackerai/packages/desktop"
    # Run the real launcher against an isolated Tauri boundary; capture the exact
    # generated configuration instead of building a Windows application.
    harness = r'''
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const files = new Map();
const cwd = process.argv[1];
const fakeFs = {
  readFileSync: (...args) => fs.readFileSync(...args),
  mkdtempSync: () => "virtual-config",
  writeFileSync: (file, body) => files.set(file, body),
  rmSync: () => {},
};
const fakeProcess = {
  argv: ["node", "run-tauri.js", process.argv[2]], platform: "win32",
  env: { STAI_FRONTEND_PORT: process.argv[3] },
  cwd: () => cwd, exit: (code) => { if (code) throw new Error(`exit ${code}`); },
};
const fakeNet = { createServer: () => {
  let onError;
  return {
    once: (_event, callback) => { onError = callback; },
    listen: (port, _host, callback) => { if (port < 1422) onError(); else callback(); },
    close: (callback) => callback(),
  };
}};
const childProcess = { spawnSync: (_command, args, options) => {
  const dynamic = args.filter((value) => files.has(value)).map((value) => JSON.parse(files.get(value)));
  console.log(JSON.stringify({ configs: dynamic, env: options.env }));
  return { status: 0 };
}};
vm.runInNewContext(fs.readFileSync(path.join(cwd, "scripts/run-tauri.js"), "utf8"), {
  process: fakeProcess, console,
  require: (name) => name === "node:fs" ? fakeFs : name === "node:net" ? fakeNet : name === "node:child_process" ? childProcess : require(name),
});
'''
    completed = subprocess.run(
        [node, "-e", harness, str(desktop), task, frontend_port], check=True, capture_output=True, text=True
    )
    result = json.loads(completed.stdout)
    configs = result["configs"]
    assert configs, "Packaged builds must receive a fallback-aware CSP"
    if expected_port is not None:
        assert configs[-1]["build"]["devUrl"] == f"http://127.0.0.1:{expected_port}"
        assert result["env"]["STAI_FRONTEND_PORT"] == str(expected_port)
        assert result["env"]["VITE_STAI_TAURI_DEV_PORT"] == str(expected_port)
    else:
        assert "build" not in configs[-1]
    csp = configs[-1]["app"]["security"]["csp"]
    for port in range(6764, 6770):
        assert f"http://127.0.0.1:{port}" in csp
    for port in range(3000, 3006):
        assert f"http://127.0.0.1:{port}" in csp
        assert f"ws://127.0.0.1:{port}" in csp
    assert "http://127.0.0.1:*" not in csp
    assert "http://*" not in csp
