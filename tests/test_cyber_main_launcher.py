import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import cyber_main
from cyber_main import _is_service_access_denied, _project_venv_python


def test_native_dev_launch_selects_free_port_for_its_own_vite_server(monkeypatch, capsys):
    monkeypatch.setattr(cyber_main.sys, "argv", ["cyber_main.py", "--desktop", "--no-open"])
    monkeypatch.setattr(cyber_main.os, "environ", {"PATH": ""})
    monkeypatch.setattr(cyber_main.os, "name", "nt")
    monkeypatch.setattr(cyber_main, "ensure_windows_protection_service", lambda _root: None)
    monkeypatch.setattr(cyber_main, "find_built_desktop_app", lambda _root: None)
    monkeypatch.setattr(cyber_main, "_http_ready", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(cyber_main, "_port_is_available", lambda _host, port: port != 1420)
    monkeypatch.setattr(cyber_main.shutil, "which", lambda *_args, **_kwargs: "runtime")
    monkeypatch.setattr(cyber_main.os.path, "isfile", lambda _path: True)
    monkeypatch.setattr(cyber_main, "build_agent_server_command", lambda *_args: None)
    process = Mock()
    process.poll.return_value = None
    monkeypatch.setattr(cyber_main.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(cyber_main.subprocess, "run", lambda *_args, **_kwargs: None)

    def stop_after_startup(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(cyber_main.time, "sleep", stop_after_startup)
    assert cyber_main.main() == 0
    assert "Protection dashboard: http://127.0.0.1:1421" in capsys.readouterr().out


class ProjectVenvLauncherTests(unittest.TestCase):
    def test_service_access_denied_is_detected_for_uac_fallback(self):
        self.assertTrue(_is_service_access_denied("[SC] StartService FAILED 5:"))
        self.assertTrue(_is_service_access_denied("Access is denied."))
        self.assertFalse(_is_service_access_denied("The service is already running."))

    def test_local_service_uses_user_scoped_entry_point(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            executable = root / "windows_protection/installer/build/Test/dist/STAIProtectionService.exe"
            executable.parent.mkdir(parents=True)
            executable.touch()
            process = Mock()
            process.poll.return_value = None
            result = Mock(returncode=1060, stdout="", stderr="")
            with (
                patch.object(cyber_main.os, "name", "nt"),
                patch.dict(cyber_main.os.environ, {"LOCALAPPDATA": temp_dir}),
                patch.object(cyber_main.subprocess, "run", return_value=result),
                patch.object(cyber_main.subprocess, "Popen", return_value=process) as spawn,
                patch.object(cyber_main, "_protection_pipe_ready", side_effect=[False, True]),
            ):
                self.assertIs(cyber_main.ensure_windows_protection_service(temp_dir), process)
            self.assertEqual(spawn.call_args.args[0], [str(executable), "--stai-local-dev"])
            self.assertEqual(spawn.call_args.kwargs["env"]["STAI_LOCAL_DEV_SERVICE"], "1")

    def test_project_venv_is_selected_for_windows_launcher(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            project_python = root / ".venv" / "Scripts" / "python.exe"
            project_python.parent.mkdir(parents=True)
            project_python.touch()

            self.assertEqual(
                _project_venv_python(
                    str(root),
                    current_executable=str(root / "system-python.exe"),
                    is_windows=True,
                ),
                str(project_python),
            )

    def test_project_venv_is_not_selected_when_already_running_in_it(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            root = Path(temp_dir)
            project_python = root / ".venv" / "Scripts" / "python.exe"
            project_python.parent.mkdir(parents=True)
            project_python.touch()

            self.assertIsNone(
                _project_venv_python(
                    str(root),
                    current_executable=str(project_python),
                    is_windows=True,
                )
            )


if __name__ == "__main__":
    unittest.main()
