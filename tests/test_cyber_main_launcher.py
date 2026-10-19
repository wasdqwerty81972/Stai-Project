import tempfile
import unittest
from pathlib import Path

from cyber_main import _is_service_access_denied, _project_venv_python


class ProjectVenvLauncherTests(unittest.TestCase):
no    def test_service_access_denied_is_detected_for_uac_fallback(self):
        self.assertTrue(_is_service_access_denied("[SC] StartService FAILED 5:"))
        self.assertTrue(_is_service_access_denied("Access is denied."))
        self.assertFalse(_is_service_access_denied("The service is already running."))

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
