from pathlib import Path

import cyber_main


def test_missing_agent_executable_does_not_close_dashboard(monkeypatch, capsys):
    monkeypatch.setattr(cyber_main.os, "environ", {"PATH": ""})
    monkeypatch.setattr(cyber_main.sys, "argv", ["cyber_main.py", "--browser", "--no-open"])
    monkeypatch.setattr(cyber_main, "ensure_windows_protection_service", lambda _root: None)
    monkeypatch.setattr(cyber_main, "_http_ready", lambda url, **_kwargs: ":3000" not in url)
    monkeypatch.setattr(cyber_main, "_port_is_available", lambda _host, _port: True)
    monkeypatch.setattr(cyber_main.shutil, "which", lambda *_args, **_kwargs: "node")
    monkeypatch.setattr(cyber_main, "build_agent_server_command", lambda *_args: ["missing-node"])
    monkeypatch.setattr(cyber_main.os.path, "isfile", lambda _path: True)

    def fail_spawn(*_args, **_kwargs):
        raise FileNotFoundError("Agent runtime was removed")

    def stop_after_startup(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(cyber_main.subprocess, "Popen", fail_spawn)
    monkeypatch.setattr(cyber_main.time, "sleep", stop_after_startup)

    assert cyber_main.main() == 0
    captured = capsys.readouterr()
    assert "Dashboard and backend are ready" in captured.out
    assert "Agent runtime was removed" in captured.err


def test_agent_runtime_uses_pinned_node_and_production_build(tmp_path: Path):
    node = tmp_path / "tools" / "node-v22.22.3" / "node.exe"
    node.parent.mkdir(parents=True)
    node.write_bytes(b"node")
    hackerai = tmp_path / "ui" / "hackerai"
    next_cli = hackerai / "node_modules" / "next" / "dist" / "bin" / "next"
    build_id = hackerai / ".next" / "BUILD_ID"
    next_cli.parent.mkdir(parents=True)
    build_id.parent.mkdir(parents=True)
    next_cli.write_text("", encoding="utf-8")
    build_id.write_text("build", encoding="utf-8")

    command = cyber_main.build_agent_server_command(str(tmp_path), "C:/node24/node.exe", 3000)

    assert command == [
        str(node), str(next_cli), "start", "--hostname", "127.0.0.1", "--port", "3000"
    ]


def test_agent_runtime_uses_pinned_node_and_webpack_dev_without_build(tmp_path: Path):
    node = tmp_path / "tools" / "node-v22.22.3" / "node.exe"
    node.parent.mkdir(parents=True)
    node.write_bytes(b"node")
    hackerai = tmp_path / "ui" / "hackerai"
    next_cli = hackerai / "node_modules" / "next" / "dist" / "bin" / "next"
    next_cli.parent.mkdir(parents=True)
    next_cli.write_text("", encoding="utf-8")

    command = cyber_main.build_agent_server_command(str(tmp_path), "C:/node24/node.exe", 3010)

    assert command == [
        str(node), str(next_cli), "dev", "--webpack", "--hostname", "127.0.0.1", "--port", "3010"
    ]
