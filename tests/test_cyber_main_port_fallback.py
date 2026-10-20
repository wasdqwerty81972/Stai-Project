from __future__ import annotations

import socket

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
