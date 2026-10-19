from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DRIVER_SERVICE = "StaiProtectionFilter"
USER_SERVICE = "STAIProtection"


def _setting(text: str, pattern: str) -> str:
    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    assert match, f"Missing installer setting matching {pattern!r}"
    return match.group(1)


def test_minifilter_has_distinct_service_identity_across_install_and_recovery():
    inf = (ROOT / "windows_protection/driver/StaiProtection.inf").read_text(encoding="utf-8")
    lifecycle = (ROOT / "windows_protection/installer/CustomActions/DriverLifecycle.cs").read_text(encoding="utf-8")
    updater = (ROOT / "windows_protection/installer/update.ps1").read_text(encoding="utf-8")
    rollback = (ROOT / "windows_protection/installer/InstallRollbackRecovery.ps1").read_text(encoding="utf-8")
    installer_builder = (ROOT / "windows_protection/installer/build-installer.ps1").read_text(encoding="utf-8")
    driver_readme = (ROOT / "windows_protection/driver/README.md").read_text(encoding="utf-8")
    service = (ROOT / "cyber_os/protection/windows_service.py").read_text(encoding="utf-8")

    names = {
        "INF": _setting(inf, r'^STAI_DRIVER_SERVICE_NAME\s*=\s*"([^"]+)"'),
        "custom action": _setting(lifecycle, r'private\s+const\s+string\s+DriverName\s*=\s*"([^"]+)"'),
        "updater": _setting(updater, r'^\$driverName\s*=\s*"([^"]+)"'),
        "rollback recovery": _setting(rollback, r'^\$driverName\s*=\s*"([^"]+)"'),
    }

    assert set(names.values()) == {DRIVER_SERVICE}, names
    assert all(name.casefold() != USER_SERVICE.casefold() for name in names.values())
    assert 'private const string ServiceName = "STAIProtection";' in lifecycle
    assert '$serviceName = "STAIProtection"' in updater
    assert '$serviceName = "STAIProtection"' in rollback
    assert '$legacyDriverName = "StaiProtection"' in updater
    assert '$legacyDriverName = "StaiProtection"' in rollback
    assert '$([regex]::Escape($driverName))' in updater
    assert '$([regex]::Escape($filterName))' in updater
    assert '$([regex]::Escape($filterName))' in rollback
    assert '_svc_name_ = "STAIProtection"' in service
    assert f'$altitudeRecord.filter_name -ne "{DRIVER_SERVICE}"' in installer_builder
    assert f'fltmc load {DRIVER_SERVICE}' in driver_readme
    assert r"\STAIProtectionPort" in (ROOT / "windows_protection/protocol/protection_protocol.h").read_text(encoding="utf-8")
    assert r"\STAIProtectionPort" in (ROOT / "cyber_os/protection/filter_client.py").read_text(encoding="utf-8")
    assert "%12%\\StaiProtection.sys" in inf
