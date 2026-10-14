from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_windows_service_build_declares_process_monitor_runtime_dependencies():
    requirements = (ROOT / "requirements-windows-protection.txt").read_text(encoding="utf-8")
    spec = (ROOT / "windows_protection" / "installer" / "pyinstaller.spec").read_text(encoding="utf-8")

    assert "psutil==7.2.2" in requirements
    assert '"psutil"' in spec
    assert '"ui.process_monitor"' in spec
    assert '"ui.windows_process_events"' in spec
    assert '"ui.device_process_identity"' in spec
    assert "ui.api_server" not in spec
