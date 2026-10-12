"""Deterministic local file protection primitives for Windows."""

from .models import DetectionRule, RuleSet, ScanVerdict
from .rule_package import InvalidRulePackage, RulePackage
from .scanner import scan_path
from .store import (
    DetectionRecord,
    ProtectionStatus,
    ProtectionStore,
    QuarantineItem,
    ScanJob,
    WindowsSecurityStatus,
)
from .quarantine import QuarantineResult, list_quarantine_items, quarantine_file, restore_quarantine
from .service import ProtectionConfig, ProtectionService
from .windows_health import WindowsSecurityStatus as HealthWindowsSecurityStatus, get_windows_security_status

__all__ = [
    "DetectionRule",
    "DetectionRecord",
    "InvalidRulePackage",
    "ProtectionConfig",
    "ProtectionService",
    "ProtectionStatus",
    "ProtectionStore",
    "QuarantineItem",
    "QuarantineResult",
    "RulePackage",
    "RuleSet",
    "ScanJob",
    "ScanVerdict",
    "WindowsSecurityStatus",
    "get_windows_security_status",
    "list_quarantine_items",
    "quarantine_file",
    "restore_quarantine",
    "scan_path",
]