"""
tests/test_tool_absence.py -- a missing binary must arrive as a fact, not as
silence.

Every shell reports "that program does not exist" differently: bash exits 127
with ``command not found``, cmd.exe exits 9009 with ``is not recognized as an
internal or external command``, PowerShell exits 1 with ``is not recognized as
the name of a cmdlet``. To a caller that only checks stdout, all three are
indistinguishable from a command that ran fine and found nothing -- which is
exactly how an absent ``nmap`` became the conclusion "no open ports". That bug
lived in all 59 per-CLI wrappers and would have survived their collapse into
``shell_exec`` untouched, because the collapse changed who runs the command, not
how absence is reported.

These tests pin one phrasing per shell end to end: the raw shell text is
recognised (``_detect_absent_binary``), the executor tags the result
(``_annotate_absence``), and ``ShellExecTool._execute`` carries the tag out to
the agent. They never spawn a real shell -- the shell's output is the fixture,
and ``execute_system_command`` is patched for the propagation tests.
"""

from __future__ import annotations

import unittest
from unittest import mock

from cyber_tools import _annotate_absence, _detect_absent_binary
from Tools_cyber.shell_exec import ShellExecTool

# Verbatim stderr from each shell asked to run a program it does not have,
# paired with the exit code that shell actually returns. Captured from a real
# run, wrapping and all -- an idealised single-line PowerShell fixture passed
# while the real thing did not, because PowerShell hard-wraps the sentence at
# the console width and the break lands in the middle of the phrase.
BASH_NOT_FOUND = "bash: line 1: nmap: command not found\n"
BASH_EXIT = 127

CMD_NOT_FOUND = (
    "'nmap' is not recognized as an internal or external command,\n"
    "operable program or batch file.\n"
)
CMD_EXIT = 9009

POWERSHELL_NOT_FOUND = (
    "nmap : The term 'nmap' is not recognized as the name of a \n"
    "cmdlet, function, script file, or operable program. Check the spelling of "
    "the name, or if a path was included, verify \n"
    "that the path is correct and try again.\n"
    "At line:1 char:1\n"
    "+ nmap 10.0.0.1\n"
    "+ ~~~~\n"
    "    + CategoryInfo          : ObjectNotFound: (nmap:String) [], CommandNotFoundException\n"
    "    + FullyQualifiedErrorId : CommandNotFoundException\n \n"
)
POWERSHELL_EXIT = 1

# The same failure on a non-English host: the prose is translated, and the wrap
# has eaten the one English phrase we could have keyed on. Only the untranslated
# exception type in the CategoryInfo line is left to recognise it by.
POWERSHELL_NOT_FOUND_LOCALIZED = (
    "nmap : Le terme « nmap » n'est pas reconnu comme nom d'applet de \n"
    "commande, fonction, fichier de script ou programme exécutable.\n"
    "At line:1 char:1\n"
    "    + CategoryInfo          : ObjectNotFound: (nmap:String) [], CommandNotFoundException\n"
    "    + FullyQualifiedErrorId : CommandNotFoundException\n"
)

# (label, environment, stderr, returncode) -- one row per shell we can spawn.
SHELLS = (
    ("bash", "wsl", BASH_NOT_FOUND, BASH_EXIT),
    ("cmd", "cmd", CMD_NOT_FOUND, CMD_EXIT),
    ("powershell", "powershell", POWERSHELL_NOT_FOUND, POWERSHELL_EXIT),
)


# ---------------------------------------------------------------------------
# _detect_absent_binary -- raw shell text -> the name of the missing program
# ---------------------------------------------------------------------------

class DetectAbsentBinaryTests(unittest.TestCase):
    def test_every_shell_phrasing_names_the_missing_binary(self) -> None:
        for label, _env, stderr, returncode in SHELLS:
            with self.subTest(shell=label):
                self.assertEqual(
                    _detect_absent_binary("", stderr, returncode),
                    "nmap",
                    f"{label} reported a missing binary and it was not recognised",
                )

    def test_absence_is_found_on_stdout_too(self) -> None:
        # The streaming path merges stderr into stdout (stderr=subprocess.STDOUT),
        # so a detector that only reads stderr sees nothing there.
        self.assertEqual(_detect_absent_binary(BASH_NOT_FOUND, "", BASH_EXIT), "nmap")

    def test_bare_bash_phrasing_without_a_line_prefix(self) -> None:
        self.assertEqual(
            _detect_absent_binary("", "nmap: command not found\n", BASH_EXIT), "nmap"
        )

    def test_powershell_prose_is_recognised_through_the_console_wrap(self) -> None:
        # The wrap point moves with the length of the binary name, so a pattern
        # spanning the whole sentence matches for a short name and silently
        # stops matching for a long one.
        long_name = "definitely_not_a_real_binary_xyz"
        wrapped = (
            f"{long_name} : The term '{long_name}' is not recognized as the name of a \n"
            "cmdlet, function, script file, or operable program.\n"
        )
        self.assertEqual(_detect_absent_binary("", wrapped, POWERSHELL_EXIT), long_name)

    def test_localized_powershell_falls_back_to_the_exception_type(self) -> None:
        # On a translated host the prose is useless; CommandNotFoundException is
        # not translated, so absence is still recognisable.
        self.assertEqual(
            _detect_absent_binary("", POWERSHELL_NOT_FOUND_LOCALIZED, POWERSHELL_EXIT),
            "nmap",
        )

    def test_a_successful_command_is_never_absent(self) -> None:
        # ``grep 'command not found' auth.log`` exits 0 and prints the phrase as a
        # *finding*. Treating that as a missing tool would discard real evidence.
        self.assertIsNone(
            _detect_absent_binary("Jan 3 auth: bash: xyz: command not found\n", "", 0)
        )

    def test_an_ordinary_failure_is_not_an_absence(self) -> None:
        # nmap exists, the run just failed: must stay an ordinary error so the
        # agent reports the failure rather than "the tool isn't installed".
        self.assertIsNone(
            _detect_absent_binary("", "Failed to resolve 'nosuchhost'.\n", 1)
        )


# ---------------------------------------------------------------------------
# _annotate_absence -- the executor's result gains a structured tag
# ---------------------------------------------------------------------------

class AnnotateAbsenceTests(unittest.TestCase):
    def test_absent_result_is_tagged_with_binary_env_and_hint(self) -> None:
        result = _annotate_absence(
            {"stdout": "", "stderr": BASH_NOT_FOUND, "returncode": BASH_EXIT}, "wsl"
        )
        self.assertEqual(result["status"], "tool_absent")
        self.assertEqual(result["binary"], "nmap")
        self.assertEqual(result["env"], "wsl")
        self.assertIn("nmap", result["hint"])
        # The hint exists to stop the model reporting an absent tool as a clean
        # result, so it has to say so in words the model will act on.
        self.assertIn("not a negative finding", result["hint"])

    def test_a_normal_result_is_left_alone(self) -> None:
        result = _annotate_absence(
            {"stdout": "Host is up.\n", "stderr": "", "returncode": 0}, "wsl"
        )
        self.assertNotIn("status", result)
        self.assertNotIn("binary", result)
        self.assertNotIn("hint", result)


# ---------------------------------------------------------------------------
# ShellExecTool._execute -- the tag survives the trip out to the agent
# ---------------------------------------------------------------------------

class ShellExecAbsencePropagationTests(unittest.TestCase):
    def test_absence_reaches_the_agent_for_every_shell(self) -> None:
        for label, environment, stderr, returncode in SHELLS:
            with self.subTest(shell=label):
                stub = _annotate_absence(
                    {"stdout": "", "stderr": stderr, "returncode": returncode},
                    environment,
                )
                with mock.patch(
                    "Tools_cyber.shell_exec.execute_system_command", return_value=stub
                ):
                    out = ShellExecTool._execute(
                        {"command": "nmap 10.0.0.1", "environment": environment}
                    )

                self.assertFalse(
                    out["success"],
                    "a command that never ran must not be reported as a success",
                )
                self.assertEqual(out["status"], "tool_absent")
                self.assertEqual(out["binary"], "nmap")
                self.assertEqual(out["env"], environment)
                self.assertEqual(out["environment"], environment)
                self.assertEqual(out["returncode"], returncode)
                self.assertIn("nmap", out["hint"])
                # An empty error string is what let the old shape read as
                # "ran, found nothing".
                self.assertTrue(out["error"].strip())

    def test_a_normal_failure_keeps_its_ordinary_shape(self) -> None:
        stub = {"stdout": "", "stderr": "Failed to resolve 'nosuchhost'.\n", "returncode": 1}
        with mock.patch(
            "Tools_cyber.shell_exec.execute_system_command", return_value=stub
        ):
            out = ShellExecTool._execute(
                {"command": "nmap nosuchhost", "environment": "wsl"}
            )

        self.assertFalse(out["success"])
        self.assertNotIn("status", out)
        self.assertNotIn("binary", out)

    def test_a_successful_run_keeps_its_ordinary_shape(self) -> None:
        stub = {"stdout": "22/tcp open ssh\n", "stderr": "", "returncode": 0}
        with mock.patch(
            "Tools_cyber.shell_exec.execute_system_command", return_value=stub
        ):
            out = ShellExecTool._execute(
                {"command": "nmap 10.0.0.1", "environment": "wsl"}
            )

        self.assertTrue(out["success"])
        self.assertNotIn("status", out)
        self.assertEqual(out["output"], "22/tcp open ssh\n")


if __name__ == "__main__":
    unittest.main()
