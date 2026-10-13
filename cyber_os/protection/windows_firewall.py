"""Narrow, SVS-owned Windows Firewall operations.

The module reads local Windows Firewall profile values and manages only
rules whose Grouping is the fixed SVS Cyber ownership marker. All write APIs
validate an IP address, use a stable rule name, and verify the resulting rule.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
from typing import Any, Callable

LOGGER = logging.getLogger("stai.protection.firewall")
GROUPING = "SVS Cyber managed rules"
RULE_PREFIX = "SVS Cyber block IP "
RULE_DESCRIPTION = "Outbound IP block created by SVS Cyber after user confirmation."


class FirewallUnavailable(RuntimeError):
    """Windows Firewall APIs could not return a reliable result."""


def _policy() -> Any:
    if __import__("os").name != "nt":
        raise FirewallUnavailable("Windows Firewall is available only on Windows")
    try:
        import win32com.client

        return win32com.client.Dispatch("HNetCfg.FwPolicy2")
    except Exception as exc:
        raise FirewallUnavailable("Windows Firewall API is unavailable") from exc


def _new_rule() -> Any:
    try:
        import win32com.client

        return win32com.client.Dispatch("HNetCfg.FWRule")
    except Exception as exc:
        raise FirewallUnavailable("Windows Firewall rule API is unavailable") from exc


def _run_com(call: Callable[[], Any], *, native_policy: bool) -> Any:
    if not native_policy or os.name != "nt":
        return call()
    try:
        import pythoncom
    except ImportError as exc:
        raise FirewallUnavailable("Windows COM runtime is unavailable") from exc
    pythoncom.CoInitialize()
    try:
        return call()
    finally:
        pythoncom.CoUninitialize()


def _native_state(policy: Any) -> dict[str, Any]:
    profiles = []
    # NET_FW_PROFILE2_DOMAIN, PRIVATE, PUBLIC
    for bit, name in ((1, "domain"), (2, "private"), (4, "public")):
        if int(policy.CurrentProfileTypes) & bit:
            profiles.append({
                "name": name,
                "enabled": bool(policy.FirewallEnabled(bit)),
                "default_inbound_action": "block" if int(policy.DefaultInboundAction(bit)) == 0 else "allow",
                "default_outbound_action": "block" if int(policy.DefaultOutboundAction(bit)) == 0 else "allow",
            })
    rules = []
    for rule in policy.Rules:
        if str(getattr(rule, "Grouping", "") or "") != GROUPING:
            continue
        rules.append({
            "rule_id": str(rule.Name),
            "name": str(rule.Name),
            "application": str(getattr(rule, "ApplicationName", "") or "") or None,
            "protocol": str(getattr(rule, "Protocol", "any")),
            "direction": "outbound" if int(rule.Direction) == 2 else "inbound",
            "remote_addresses": str(getattr(rule, "RemoteAddresses", "") or ""),
            "action": "block" if int(rule.Action) == 0 else "allow",
            "profiles": int(getattr(rule, "Profiles", 0)),
            "enabled": bool(rule.Enabled),
            "owner": GROUPING,
        })
    return {"profiles": profiles, "managed_rules": rules}


def _matches_ip_block(rule: Any, address: str) -> bool:
    try:
        return (
            str(getattr(rule, "Grouping", "") or "") == GROUPING
            and bool(rule.Enabled)
            and int(rule.Direction) == 2
            and int(rule.Action) == 0
            and int(rule.Protocol) == 256
            and int(rule.Profiles) == 0x7FFFFFFF
            and str(rule.RemoteAddresses).strip() == address
        )
    except Exception:
        return False


class WindowsFirewallManager:
    """Read effective firewall state and modify only explicitly managed rules."""

    def __init__(
        self,
        policy_factory: Callable[[], Any] | None = None,
        rule_factory: Callable[[], Any] | None = None,
    ) -> None:
        self._policy_factory = policy_factory or _policy
        self._rule_factory = rule_factory or _new_rule
        self._native_policy = policy_factory is None

    def snapshot(self) -> dict[str, Any]:
        try:
            data = _run_com(lambda: _native_state(self._policy_factory()), native_policy=self._native_policy)
        except Exception as exc:
            LOGGER.info("Windows Firewall status unavailable: %s", type(exc).__name__)
            return {
                "state": "unavailable",
                "protection": "unavailable",
                "source": "Windows Firewall COM API (local policy view; Group Policy may override)",
                "profiles": None,
                "managed_rules": None,
                "error": "Windows Firewall status could not be read",
            }
        enabled_count = sum(1 for profile in data["profiles"] if profile["enabled"])
        protection = (
            "unavailable" if not data["profiles"] else
            "enabled" if enabled_count == len(data["profiles"]) else
            "partial" if enabled_count else "disabled"
        )
        return {
            "state": "active",
            "protection": protection,
            "source": "Windows Firewall COM API (local policy view; Group Policy may override)",
            **data,
            "error": None,
        }

    @staticmethod
    def _normalize_ip(value: str) -> str:
        try:
            parsed = ipaddress.ip_address(value.strip())
        except (ValueError, AttributeError) as exc:
            raise ValueError("remote_address must be a valid IPv4 or IPv6 address") from exc
        if parsed.is_multicast or not parsed.is_global:
            raise ValueError("only globally routable unicast addresses can be blocked here")
        return str(parsed)

    @classmethod
    def rule_id_for_ip(cls, address: str) -> str:
        normalized = cls._normalize_ip(address)
        digest = hashlib.sha256(normalized.encode("ascii")).hexdigest()[:16]
        return f"{RULE_PREFIX}{digest}"

    def block_remote_ip(self, address: str) -> dict[str, Any]:
        normalized = self._normalize_ip(address)
        return _run_com(lambda: self._block_remote_ip(normalized), native_policy=self._native_policy)

    def _block_remote_ip(self, normalized: str) -> dict[str, Any]:
        name = self.rule_id_for_ip(normalized)
        policy = self._policy_factory()
        rules = policy.Rules
        try:
            existing = rules.Item(name)
            if not _matches_ip_block(existing, normalized):
                raise FirewallUnavailable("rule identifier conflicts with an unexpected firewall rule")
            return {"success": True, "created": False, "rule_id": name, "remote_address": normalized}
        except FirewallUnavailable:
            raise
        except Exception:
            pass

        rule = self._rule_factory()
        rule.Name = name
        rule.Description = RULE_DESCRIPTION
        rule.Grouping = GROUPING
        rule.Enabled = True
        rule.Direction = 2  # NET_FW_RULE_DIR_OUT
        rule.Action = 0  # NET_FW_ACTION_BLOCK
        rule.Protocol = 256  # NET_FW_IP_PROTOCOL_ANY
        rule.RemoteAddresses = normalized
        rule.Profiles = 0x7FFFFFFF
        policy.Rules.Add(rule)
        verified = rules.Item(name)
        if (
            not _matches_ip_block(verified, normalized)
        ):
            try:
                rules.Remove(name)
            except Exception:
                LOGGER.exception("failed to roll back an unverified SVS firewall rule")
            raise FirewallUnavailable("Windows did not confirm the firewall rule")
        return {"success": True, "created": True, "rule_id": name, "remote_address": normalized}

    def remove_managed_rule(self, rule_id: str) -> dict[str, Any]:
        if not isinstance(rule_id, str) or not rule_id.startswith(RULE_PREFIX) or len(rule_id) != len(RULE_PREFIX) + 16:
            raise ValueError("rule_id is not an SVS-managed IP rule")
        return _run_com(lambda: self._remove_managed_rule(rule_id), native_policy=self._native_policy)

    def _remove_managed_rule(self, rule_id: str) -> dict[str, Any]:
        policy = self._policy_factory()
        rules = policy.Rules
        try:
            rule = rules.Item(rule_id)
        except Exception:
            return {"success": True, "removed": False, "rule_id": rule_id}
        try:
            address = str(rule.RemoteAddresses).strip()
            is_owned = (
                str(rule.Name) == rule_id
                and self.rule_id_for_ip(address) == rule_id
                and str(getattr(rule, "Description", "") or "") == RULE_DESCRIPTION
                and _matches_ip_block(rule, address)
            )
        except (AttributeError, ValueError):
            is_owned = False
        if not is_owned:
            raise FirewallUnavailable("refusing to remove a rule not owned by SVS Cyber")
        rules.Remove(rule_id)
        try:
            rules.Item(rule_id)
        except Exception:
            return {"success": True, "removed": True, "rule_id": rule_id}
        raise FirewallUnavailable("Windows did not confirm removal of the managed rule")
