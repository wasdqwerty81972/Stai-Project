"""
tests/test_tool_registry_consistency.py — Every tool name the runtime hardcodes
must answer to a real registered tool.

The bugs these pin are all silent. A subagent allowlist naming a tool that was
never registered just means that specialist never calls it and reports "no
anomaly indicators". A PROTECTED_TOOLS entry no tool answers to protects
nothing, so the compactor prunes state it was told to keep. A second
``def register_all_default_tools`` shadows the first, so tools registered only
in the shadowed copy disappear from the catalog with no error anywhere.
"""

from __future__ import annotations

import ast
import difflib
import glob
import os
import unittest
from typing import Set

from cyber_tools import AuditLogger, ToolRegistry, register_all_default_tools

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _live_registry() -> ToolRegistry:
    registry = ToolRegistry(AuditLogger())
    register_all_default_tools(registry)
    return registry


def _live_tool_names() -> Set[str]:
    return set(_live_registry().tools)


class _RegistryTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = _live_registry()
        cls.live = set(cls.registry.tools)


class RegistrationIsSingleDefinitionTests(_RegistryTestCase):
    """cyber_tools.py once carried two ``register_all_default_tools`` bodies."""

    def test_register_all_default_tools_is_defined_exactly_once(self) -> None:
        source = open(os.path.join(PROJECT_ROOT, "cyber_tools.py"), encoding="utf-8").read()
        tree = ast.parse(source)
        defs = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "register_all_default_tools"
        ]
        self.assertEqual(
            len(defs),
            1,
            "A duplicate definition shadows the earlier one, so any tool registered "
            f"only in the shadowed copy is silently absent. Found at lines "
            f"{[d.lineno for d in defs]}.",
        )

    def test_threat_intel_tools_survived_the_deduplication(self) -> None:
        # These four were registered only in the shadowed duplicate at one point.
        for name in ("abuseipdb_check", "shodan_lookup", "urlscan_check", "virustotal_hash_lookup"):
            with self.subTest(tool=name):
                self.assertIn(name, self.live)

    def test_registry_carries_the_full_catalog(self) -> None:
        # A collapse to a handful of tools means registration aborted partway.
        #
        # The floor used to be >150, which only worked while the catalog held
        # 59 single-command CLI wrappers. Those collapsed into one unified
        # shell_exec, so the count is no longer a proxy for completeness: a
        # legitimate consolidation and a registration that died halfway both
        # lower it. The floor is kept as a coarse backstop and paired with
        # test_every_registration_family_is_represented, which is what actually
        # catches a partial abort now.
        self.assertGreater(len(self.live), 100)

    def test_every_registration_family_is_represented(self) -> None:
        """One representative per registration block in register_all_default_tools.

        Each block is wrapped in its own try/except that calls
        _skip_optional_tool_group on failure, so a block can vanish entirely
        while the total count stays plausible. Counting cannot see that; naming
        can. A family that is deliberately retired should be deleted from this
        list in the same commit that retires it.
        """
        representatives = {
            "threat intel": "abuseipdb_check",
            "workspace": "workspace_read_file",
            "network": "network_inspect",
            "forensics": "static_analysis",
            "secrets": "secret_scan",
            "web recon": "web_security_headers",
            "osint": "osint_subdomain_enum",
            "tls": "tls_cert_inspect",
            "database": "db_create_case",
            "email": "email_header_analysis",
            "cloud": "cloud_s3_check",
            "command layer": "shell_exec",
        }
        for family, tool in representatives.items():
            with self.subTest(family=family, tool=tool):
                self.assertIn(
                    tool,
                    self.live,
                    f"the {family} registration block produced nothing; its "
                    "try/except swallowed the failure into a skip notice",
                )


class SubagentAllowlistTests(_RegistryTestCase):
    def test_every_allowlisted_tool_is_registered(self) -> None:
        from cyber_os.subagents.profiles import DEFENSIVE_SPECIALIST_PROFILES

        for profile, definition in DEFENSIVE_SPECIALIST_PROFILES.items():
            for tool in definition.allowed_tools:
                with self.subTest(profile=profile.name, tool=tool):
                    self.assertIn(
                        tool,
                        self.live,
                        f"{profile.name} is allowed to call '{tool}', but no such tool "
                        "is registered, so the specialist can never use it.",
                    )

    def test_profiles_are_not_empty(self) -> None:
        from cyber_os.subagents.contracts import SubagentProfile
        from cyber_os.subagents.profiles import DEFENSIVE_SPECIALIST_PROFILES

        # The Network Containment Advisor is intentionally advisory-only: it
        # reasons over parent-supplied evidence and holds no tools so it can
        # never itself execute containment. Its empty allowlist is a verified
        # safety property (see test_defensive_swarm.py), not a mistake.
        TOOLLESS_BY_DESIGN = {SubagentProfile.NETWORK_CONTAINMENT_ADVISOR}

        self.assertGreater(len(DEFENSIVE_SPECIALIST_PROFILES), 0)
        for profile, definition in DEFENSIVE_SPECIALIST_PROFILES.items():
            if profile in TOOLLESS_BY_DESIGN:
                continue
            with self.subTest(profile=profile.name):
                self.assertTrue(definition.allowed_tools, "a specialist with no tools cannot act")


class ProtectedToolTests(_RegistryTestCase):
    def test_protected_tools_all_exist(self) -> None:
        from cyber_os.compaction import PROTECTED_TOOLS

        for tool in PROTECTED_TOOLS:
            with self.subTest(tool=tool):
                self.assertIn(
                    tool,
                    self.live,
                    f"'{tool}' is marked un-prunable but is not a registered tool, "
                    "so the protection applies to nothing.",
                )


class HardcodedToolNameTests(_RegistryTestCase):
    """Any ``execute_tool("literal")`` in the runtime must name a real tool.

    ``SCANNED_CALLEES`` includes the subagent manager's own ``_call_scoped_tool``
    wrapper. Specialist delegations go through that, not ``execute_tool``
    directly, so scanning only the latter left the delegation path unguarded —
    which is exactly where the wrong-argument bug lived.
    """

    SCANNED = ("cyber_os/**/*.py", "ui/*.py")
    SCANNED_CALLEES = ("execute_tool", "_call_scoped_tool")

    def test_execute_tool_literals_resolve(self) -> None:
        unresolved = []
        files = [os.path.join(PROJECT_ROOT, "cyber_agent.py")]
        for pattern in self.SCANNED:
            files.extend(glob.glob(os.path.join(PROJECT_ROOT, pattern), recursive=True))

        for path in files:
            try:
                tree = ast.parse(open(path, encoding="utf-8").read())
            except (SyntaxError, UnicodeDecodeError):
                continue
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and getattr(node.func, "attr", None) in self.SCANNED_CALLEES
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and node.args[0].value not in self.live
                ):
                    rel = os.path.relpath(path, PROJECT_ROOT)
                    unresolved.append(f"{rel}:{node.lineno} execute_tool('{node.args[0].value}')")

        self.assertEqual(
            unresolved,
            [],
            "These calls name tools that are not registered; each one fails at "
            "runtime with an unknown-tool error:\n  " + "\n  ".join(unresolved),
        )

    def test_execute_tool_literal_arguments_match_the_signature(self) -> None:
        """A literal argument dict must use the tool's own parameter names.

        Names alone are not enough. The subagent manager called
        ``virustotal_hash_lookup`` with ``hash`` and ``virustotal_ip_lookup``
        with ``ip`` while the tools accept ``file_hash``/``ip_address``: every
        threat-intel delegation raised TypeError inside the tool and was
        reported to the user as a failed specialist.
        """
        import inspect

        from cyber_tools import ToolDefinition

        mismatches = []
        files = [os.path.join(PROJECT_ROOT, "cyber_agent.py")]
        for pattern in ("cyber_os/**/*.py", "ui/**/*.py", "Tools_cyber/**/*.py"):
            files.extend(glob.glob(os.path.join(PROJECT_ROOT, pattern), recursive=True))

        for path in files:
            try:
                tree = ast.parse(open(path, encoding="utf-8").read())
            except (SyntaxError, UnicodeDecodeError):
                continue
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call)
                    and getattr(node.func, "attr", None) in self.SCANNED_CALLEES
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                ):
                    continue
                name = node.args[0].value
                tool = self.registry.tools.get(name)
                func = getattr(tool, "python_func", None) if tool else None
                if not isinstance(tool, ToolDefinition) or not callable(func):
                    continue
                try:
                    signature = inspect.signature(func)
                except (TypeError, ValueError):
                    continue
                if any(p.kind == p.VAR_KEYWORD for p in signature.parameters.values()):
                    continue
                if len(node.args) < 2 or not isinstance(node.args[1], ast.Dict):
                    continue
                accepted = {
                    p.name
                    for p in signature.parameters.values()
                    if p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
                }
                required = {
                    p.name
                    for p in signature.parameters.values()
                    if p.default is p.empty
                    and p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
                }
                supplied = {
                    k.value for k in node.args[1].keys if isinstance(k, ast.Constant)
                }
                rel = os.path.relpath(path, PROJECT_ROOT)
                for key in sorted(supplied - accepted):
                    near = difflib.get_close_matches(str(key), sorted(accepted), n=2, cutoff=0.5)
                    hint = f" (did you mean {near}?)" if near else ""
                    mismatches.append(
                        f"{rel}:{node.lineno} {name}: argument '{key}' is not in {signature}{hint}"
                    )
                for missing in sorted(required - supplied):
                    mismatches.append(
                        f"{rel}:{node.lineno} {name}: missing required argument '{missing}' for {signature}"
                    )

        self.assertEqual(
            mismatches,
            [],
            "These calls would raise TypeError inside the tool:\n  " + "\n  ".join(mismatches),
        )

    def test_role_recommended_tools_resolve(self) -> None:
        source = open(os.path.join(PROJECT_ROOT, "cyber_agent.py"), encoding="utf-8").read()
        declared = set()
        for node in ast.walk(ast.parse(source)):
            if (
                isinstance(node, ast.keyword)
                and node.arg in ("tools", "recommended_tools")
                and isinstance(node.value, ast.List)
            ):
                declared.update(
                    element.value
                    for element in node.value.elts
                    if isinstance(element, ast.Constant) and isinstance(element.value, str)
                )

        self.assertTrue(declared, "no tool declarations found — the scan is looking in the wrong place")
        self.assertEqual(
            sorted(declared - self.live),
            [],
            "roles and workflow steps recommend tools that do not exist",
        )


if __name__ == "__main__":
    unittest.main()
