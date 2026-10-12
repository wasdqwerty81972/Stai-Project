"""Windows Security Center status reader (read-only)."""

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class WindowsSecurityStatus:
    registered_av_provider: Optional[str]
    defender_mode: Optional[str]
    query_available: bool


def get_windows_security_status() -> WindowsSecurityStatus:
    """
    Read Windows Security Center status for registered AV provider and Defender mode.

    This is read-only - never modifies system configuration.
    Returns unavailable status on non-Windows or when queries fail.
    """
    if platform.system() != "Windows":
        return WindowsSecurityStatus(None, None, False)

    provider = _get_registered_av_provider()
    defender_mode = _get_defender_mode()

    return WindowsSecurityStatus(
        registered_av_provider=provider,
        defender_mode=defender_mode,
        query_available=provider is not None or defender_mode is not None,
    )


def _get_registered_av_provider() -> Optional[str]:
    """Query WMI for registered antivirus product."""
    try:
        # Use PowerShell to query WMI Security Center
        ps_script = """
        try {
            $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
            if ($av) {
                $av | Select-Object -First 1 -ExpandProperty displayName
            }
        } catch {}
        """
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout.strip()
        return output if output else None
    except Exception:
        return None


def _get_defender_mode() -> Optional[str]:
    """Query Windows Defender real-time protection status."""
    try:
        ps_script = """
        try {
            $prefs = Get-MpPreference
            if ($prefs.DisableRealtimeMonitoring) {
                "disabled"
            } else {
                "enabled"
            }
        } catch {}
        """
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout.strip().lower()
        if output in ("enabled", "disabled"):
            return output
        return None
    except Exception:
        return None