"""
tests/test_shell_exec.py -- unit coverage for the unified shell_exec tool's
pure helpers.

Collapsing 59 per-CLI wrapper tools into one ``shell_exec`` moved the safety
guarantee out of fixed per-tool ``command_template`` strings and into two pure
functions: ``build_preset_command`` (a preset id + params -> a concretely quoted
``(command, environment, interpreter)``) and ``resolve_risk`` (the
per-invocation risk verdict the executor gates on). These tests exercise ONLY
those pure functions plus the ``_quote`` / ``_substitute`` primitives they rely
on -- they never call ``ShellExecTool.run``/``_execute`` and so never spawn a
real shell. The properties under test: preset routing to the right
interpreter/environment, an injection payload staying a single quoted token so
the command's structure is preserved, and risk failing closed to DESTRUCTIVE
whenever a call cannot prove itself safe.
"""

from __future__ import annotations

import shlex
import unittest
from types import SimpleNamespace
from unittest import mock

from Tools_cyber import shell_exec
from Tools_cyber.shell_exec import (
    MissingParameterError,
    UnknownPresetError,
    _classify_final,
    _quote,
    _substitute,
    build_preset_command,
    resolve_risk,
)
from cyber_tools import RiskLevel


# Ascending blast radius, mirrored locally so "MODIFIES_SYSTEM or higher" can be
# asserted as an ordering rather than an exact tier (robust to catalogue tweaks).
_RISK_ORDER = (
    RiskLevel.READ_ONLY,
    RiskLevel.MODIFIES_SYSTEM,
    RiskLevel.DESTRUCTIVE,
    RiskLevel.KERNEL_INTERVENTION,
)


def _rank(level: RiskLevel) -> int:
    return _RISK_ORDER.index(level)


# ---------------------------------------------------------------------------
# build_preset_command -- preset id + params -> (command, environment, interp)
# ---------------------------------------------------------------------------

class BuildPresetCommandTests(unittest.TestCase):
    def test_nmap_preset_builds_a_bash_wsl_command(self) -> None:
        command, environment, interpreter = build_preset_command(
            "nmap_scan", {"target": "10.0.0.1"}
        )
        self.assertEqual(command, "nmap 10.0.0.1")
        self.assertEqual(environment, "wsl")
        self.assertEqual(interpreter, "bash")

    def test_powershell_preset_script_is_unwrapped(self) -> None:
        """A powershell preset returns the bare script body; the executor's
        execute_system_command re-adds the ``-Command`` wrapper itself."""
        command, environment, interpreter = build_preset_command(
            "get_winevent", {"log_name": "Security"}
        )
        self.assertEqual(environment, "powershell")
        self.assertEqual(interpreter, "powershell")
        lowered = command.lower()
        self.assertFalse(lowered.startswith("powershell -command"))
        self.assertFalse(lowered.startswith("powershell"))
        # The substituted parameter is present in the (quoted) script body.
        self.assertIn("Security", command)

    def test_defender_scan_routes_to_powershell_via_call_operator(self) -> None:
        command, environment, interpreter = build_preset_command(
            "windows_defender_scan", {"target": "C:/tmp"}
        )
        self.assertEqual(environment, "powershell")
        self.assertEqual(interpreter, "powershell")
        # The '&' call-operator head is what forces the powershell environment.
        self.assertTrue(command.strip().startswith("&"))
        self.assertIn("C:/tmp", command)

    def test_injection_payload_stays_a_single_quoted_bash_token(self) -> None:
        """A ``;``-laden target cannot break out of its argument: it is emitted
        as one shlex-quoted token, so the command's structure is preserved and
        the ``;`` stays inside the quotes as inert data."""
        command, environment, interpreter = build_preset_command(
            "nmap_scan", {"target": "10.0.0.1; rm -rf /"}
        )
        self.assertEqual(command, "nmap '10.0.0.1; rm -rf /'")
        self.assertEqual(environment, "wsl")
        self.assertEqual(interpreter, "bash")

    def test_unknown_preset_raises(self) -> None:
        with self.assertRaises(UnknownPresetError):
            build_preset_command("does_not_exist", {})


# ---------------------------------------------------------------------------
# _quote -- exactly one quoted token per interpreter, no breakout
# ---------------------------------------------------------------------------

class QuoteTests(unittest.TestCase):
    def test_bash_uses_shlex_quoting(self) -> None:
        self.assertEqual(_quote("plain", "bash"), "plain")
        self.assertEqual(_quote("a b", "bash"), "'a b'")
        for value in ("10.0.0.1; rm -rf /", "a'b", "$(whoami)", "a|b"):
            with self.subTest(value=value):
                self.assertEqual(_quote(value, "bash"), shlex.quote(value))

    def test_powershell_single_quotes_and_doubles_internal_quotes(self) -> None:
        self.assertEqual(_quote("O'Brien", "powershell"), "'O''Brien'")
        self.assertEqual(_quote("plain", "powershell"), "'plain'")

    def test_cmd_wraps_in_double_quotes_and_strips_percent_and_bang(self) -> None:
        # % and ! expand even inside cmd double quotes, so they are stripped.
        self.assertEqual(_quote("a%b!c", "cmd"), '"abc"')
        # Internal double quotes are doubled, not dropped.
        self.assertEqual(_quote('say "hi"', "cmd"), '"say ""hi"""')

    def test_nul_byte_is_refused_for_every_interpreter(self) -> None:
        for interpreter in ("bash", "powershell", "cmd"):
            with self.subTest(interpreter=interpreter):
                with self.assertRaises(ValueError):
                    _quote("bad\x00value", interpreter)


# ---------------------------------------------------------------------------
# _substitute -- placeholder fill with interpreter-correct quoting
# ---------------------------------------------------------------------------

class SubstituteTests(unittest.TestCase):
    def test_missing_parameter_raises(self) -> None:
        with self.assertRaises(MissingParameterError):
            _substitute("nmap {target}", {}, "bash")

    def test_placeholder_is_filled_and_quoted(self) -> None:
        self.assertEqual(
            _substitute("nmap {target}", {"target": "10.0.0.1"}, "bash"),
            "nmap 10.0.0.1",
        )
        self.assertEqual(
            _substitute("nmap {target}", {"target": "a b"}, "bash"),
            "nmap 'a b'",
        )

    def test_author_quotes_around_a_placeholder_are_not_double_applied(self) -> None:
        # A single layer of matching quotes in the template is replaced by
        # canonical quoting rather than nested inside it.
        self.assertEqual(
            _substitute("nmap '{target}'", {"target": "a b"}, "bash"),
            "nmap 'a b'",
        )


# ---------------------------------------------------------------------------
# resolve_risk -- the per-invocation classifier; fails closed to DESTRUCTIVE
# ---------------------------------------------------------------------------

class ResolveRiskTests(unittest.TestCase):
    def test_nmap_preset_resolves_read_only(self) -> None:
        self.assertEqual(
            resolve_risk(preset="nmap_scan", params={"target": "10.0.0.1"}),
            RiskLevel.READ_ONLY,
        )

    def test_injection_does_not_escalate_a_read_only_preset(self) -> None:
        """Quoting keeps the payload as data, so the classifier still sees one
        nmap invocation: the verdict must not be DESTRUCTIVE-by-injection."""
        risk = resolve_risk(
            preset="nmap_scan", params={"target": "10.0.0.1; rm -rf /"}
        )
        self.assertNotEqual(risk, RiskLevel.DESTRUCTIVE)

    def test_metasploit_preset_is_destructive(self) -> None:
        self.assertEqual(
            resolve_risk(preset="metasploit_console", params={"command": "version"}),
            RiskLevel.DESTRUCTIVE,
        )

    def test_freeform_interpreter_command_is_never_read_only(self) -> None:
        # A hand-written command can never earn READ_ONLY auto-approval.
        risk = resolve_risk(command="Get-Process", environment="powershell")
        self.assertNotEqual(risk, RiskLevel.READ_ONLY)
        self.assertGreaterEqual(_rank(risk), _rank(RiskLevel.MODIFIES_SYSTEM))

    def test_freeform_destructive_command_is_destructive(self) -> None:
        self.assertEqual(
            resolve_risk(command="rm -rf /", environment="wsl"),
            RiskLevel.DESTRUCTIVE,
        )

    def test_unknown_preset_fails_closed(self) -> None:
        self.assertEqual(
            resolve_risk(preset="does_not_exist"), RiskLevel.DESTRUCTIVE
        )

    def test_missing_required_param_fails_closed(self) -> None:
        self.assertEqual(
            resolve_risk(preset="nmap_scan", params={}), RiskLevel.DESTRUCTIVE
        )


# ---------------------------------------------------------------------------
# Classifier-as-floor and admin escalation -- the two invariants that keep a
# *frozen* preset risk from being the last word. These are asserted with the
# classifier stubbed so the property under test is the combining rule itself,
# not whatever verdict the live catalogue happens to produce today.
# ---------------------------------------------------------------------------

def _fake_preset(risk_level: str, requires_admin: bool = False) -> SimpleNamespace:
    """A minimal stand-in carrying only the attributes shell_exec reads."""
    return SimpleNamespace(
        argv_template=["whoami"],
        env="wsl_linux",
        risk_level=risk_level,
        requires_admin=requires_admin,
    )


class ClassifierFloorTests(unittest.TestCase):
    def test_classified_verdict_escalates_a_read_only_preset(self) -> None:
        """A preset's frozen risk is a floor, not a ceiling: the *substituted*
        command is classified too and the worse verdict wins. This is what makes
        a hypothetical quoting bug survivable -- an injected destructive payload
        in the final string still forces approval."""
        args = {"preset": "nmap_scan", "params": {"target": "10.0.0.1"}}
        self.assertEqual(resolve_risk(**args), RiskLevel.READ_ONLY)
        with mock.patch.object(
            shell_exec, "_classify_final", return_value=RiskLevel.DESTRUCTIVE
        ):
            self.assertEqual(resolve_risk(**args), RiskLevel.DESTRUCTIVE)

    def test_lenient_classifier_cannot_downgrade_a_frozen_preset(self) -> None:
        """The floor cuts both ways: a vetted-DESTRUCTIVE preset is not softened
        by a classifier that fails to recognise it."""
        with mock.patch.object(
            shell_exec, "_classify_final", return_value=RiskLevel.READ_ONLY
        ):
            self.assertEqual(
                resolve_risk(preset="metasploit_console", params={"command": "version"}),
                RiskLevel.DESTRUCTIVE,
            )


class AdminEscalationTests(unittest.TestCase):
    def test_admin_preset_never_resolves_read_only(self) -> None:
        """I5 at the preset layer: a preset frozen READ_ONLY but flagged
        requires_admin resolves to MODIFIES_SYSTEM, so it can never be silently
        auto-approved. The classifier is stubbed to READ_ONLY to prove the
        escalation comes from the requires_admin rule alone."""
        preset = _fake_preset("READ_ONLY", requires_admin=True)
        with mock.patch.dict(
            shell_exec.COMMAND_PRESETS, {"_test_admin_read": preset}, clear=False
        ), mock.patch.object(
            shell_exec, "_classify_final", return_value=RiskLevel.READ_ONLY
        ):
            risk = resolve_risk(preset="_test_admin_read")
        self.assertEqual(risk, RiskLevel.MODIFIES_SYSTEM)

    def test_admin_verdict_never_classifies_read_only(self) -> None:
        """I5 at the classifier layer: a READ_ONLY verdict that also reports
        requires_admin is raised to MODIFIES_SYSTEM."""
        verdict = SimpleNamespace(
            level="READ_ONLY", undecidable=False, requires_admin=True
        )
        with mock.patch.object(shell_exec, "classify_command", return_value=verdict):
            self.assertEqual(
                _classify_final("whoami", "bash", True), RiskLevel.MODIFIES_SYSTEM
            )

    def test_unparsable_preset_risk_label_fails_closed(self) -> None:
        """A catalogue entry whose risk_level string is not a RiskLevel member
        must not fall through as safe."""
        preset = _fake_preset("NOT_A_REAL_LEVEL")
        with mock.patch.dict(
            shell_exec.COMMAND_PRESETS, {"_test_bad_label": preset}, clear=False
        ), mock.patch.object(
            shell_exec, "_classify_final", return_value=RiskLevel.READ_ONLY
        ):
            risk = resolve_risk(preset="_test_bad_label")
        self.assertEqual(risk, RiskLevel.DESTRUCTIVE)


class ClassifyFinalFailClosedTests(unittest.TestCase):
    def test_missing_classifier_is_destructive(self) -> None:
        """If cyber_os.policy is unavailable the module-level import guard leaves
        classify_command as None; nothing may be approved on that basis."""
        with mock.patch.object(shell_exec, "classify_command", None):
            self.assertEqual(
                _classify_final("echo hi", "bash", False), RiskLevel.DESTRUCTIVE
            )

    def test_undecidable_verdict_is_destructive(self) -> None:
        verdict = SimpleNamespace(
            level="READ_ONLY", undecidable=True, requires_admin=False
        )
        with mock.patch.object(shell_exec, "classify_command", return_value=verdict):
            self.assertEqual(
                _classify_final("something odd", "bash", False), RiskLevel.DESTRUCTIVE
            )

    def test_unknown_verdict_level_is_destructive(self) -> None:
        verdict = SimpleNamespace(
            level="SOMEWHAT_SPICY", undecidable=False, requires_admin=False
        )
        with mock.patch.object(shell_exec, "classify_command", return_value=verdict):
            self.assertEqual(
                _classify_final("something odd", "bash", False), RiskLevel.DESTRUCTIVE
            )


if __name__ == "__main__":
    unittest.main()
