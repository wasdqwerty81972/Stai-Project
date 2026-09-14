"""
Shell Execution Tool — Generic PowerShell / WSL / CMD command runner.

Allows the AI agent to execute arbitrary shell commands through the existing
STAI execute_system_command infrastructure. Every invocation flows through
the normal CyberAgent pipeline: environment routing, guardrail approval,
audit logging, and UI events.

Risk: MODIFIES_SYSTEM — arbitrary commands can alter the host. READ_ONLY
commands are auto-approved (via the guardrail manager); anything that
modifies state requires explicit operator confirmation or a high threat
score.

Usage (via CyberToolsClient):
    python cyber_tools_template.py call shell_exec --input '{"command": "Get-Process", "environment": "powershell"}'
    python cyber_tools_template.py call shell_exec --input '{"command": "ls -la /tmp", "environment": "wsl"}'
"""

from typing import Any, Dict
from cyber_tools import CyberToolPlugin, RiskLevel, execute_system_command


class ShellExecTool(CyberToolPlugin):
    """Execute an arbitrary shell command in PowerShell, WSL bash, or CMD.

    Arguments
    ---------
    command : str
        The command string to execute.
    environment : str  (default "powershell")
        One of "powershell", "wsl", or "cmd".
    timeout : int      (default 15)
        Maximum execution time in seconds.
    """

    name = "shell_exec"
    description = (
        "Execute an arbitrary PowerShell, WSL (bash), or CMD command with "
        "full guardrail, audit, and timeout support. Risk-gated at "
        "MODIFIES_SYSTEM."
    )
    version = "1.0.0"
    environments = ["cross_platform"]
    requires_admin = False
    risk_level = RiskLevel.MODIFIES_SYSTEM

    # ------------------------------------------------------------------
    # CyberToolPlugin.run  — called by CyberAgent.execute_tool when the
    # ToolDefinition was built from a dynamic plugin (python_func path is
    # bypassed for plugins; run() is the entry point instead).
    # ------------------------------------------------------------------
    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self._execute(arguments)

    # ------------------------------------------------------------------
    # Standalone callable — registered as python_func when wired into the
    # default tool catalog manually, and also used internally.
    # ------------------------------------------------------------------
    @staticmethod
    def _execute(arguments: Dict[str, Any]) -> Dict[str, Any]:
        command = arguments.get("command", "")
        environment = str(arguments.get("environment", "powershell")).lower()
        timeout = arguments.get("timeout", 15)

        # --- Validate command ---
        if not command or not command.strip():
            return {
                "success": False,
                "output": "",
                "error": "Missing 'command' argument. Provide a command string to execute.",
            }

        # --- Validate environment ---
        valid_envs = {"powershell", "wsl", "cmd"}
        if environment not in valid_envs:
            return {
                "success": False,
                "output": "",
                "error": (
                    f"Invalid environment '{environment}'. "
                    f"Must be one of: {', '.join(sorted(valid_envs))}."
                ),
            }

        # --- Validate / coerce timeout ---
        try:
            timeout = int(timeout)
            if timeout < 1:
                timeout = 15
        except (TypeError, ValueError):
            timeout = 15
        if timeout > 300:
            timeout = 300  # hard cap to prevent runaway processes

        # --- Delegate to the shared infrastructure ---
        result = execute_system_command(
            command=command,
            environment=environment,
            timeout=timeout,
        )

        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        returncode = result.get("returncode", -1)
        error = result.get("error", "")

        # If the executor itself failed (e.g. timeout / subprocess error)
        if error and returncode != 0:
            return {
                "success": False,
                "output": stdout,
                "error": error,
                "returncode": returncode,
                "environment": environment,
            }

        return {
            "success": returncode == 0,
            "output": stdout,
            "error": stderr or "",
            "returncode": returncode,
            "environment": environment,
        }

    def run_safe(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Alias kept for callers that use run_safe."""
        return self._execute(arguments)


TOOL_CLASS = ShellExecTool
