from pathlib import Path

import cyber_main


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
