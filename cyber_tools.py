"""
Cybersecurity Tools Module (cyber_tools.py)

Provides defensive diagnostics, WSL environment detection, conditional tool routing,
auditing, static analysis, fallback mappings, and least-privilege guardrails.
"""

import os
import sys
import json
import shutil
import hashlib
import subprocess
import time
import ast
import re
import string
import threading
import importlib.util
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Callable, Type
from enum import Enum

# --- Optional KeyManager Integration ---
try:
    from key_manager import AiApi
    KEY_MANAGER_AVAILABLE = True
except Exception:
    KEY_MANAGER_AVAILABLE = False
    AiApi = None

# --- Optional Threat Intelligence Integration (VirusTotal, AlienVault OTX) ---
# Requires VIRUSTOTAL_API_KEY / OTX_API_KEY in the environment. Without them the
# lookups below report verdict="unknown" rather than a clean result.
try:
    from cyber_threat_intel import ThreatIntelManager
    THREAT_INTEL_AVAILABLE = True
except Exception:
    THREAT_INTEL_AVAILABLE = False
    ThreatIntelManager = None

_OPTIONAL_TOOL_GROUPS_SKIPPED: List[str] = []
_SKIP_SUMMARY_REPORTED = False


def _skip_optional_tool_group(group: str, reason: BaseException) -> None:
    """Record an optional tool group that could not be registered.

    These groups depend on packages that may not be installed (cyber_db,
    vigil_tools, cyber_soc_engine). Swallowing the failure silently made tools
    disappear from the agent's catalog with no way to tell what was missing.
    """
    _OPTIONAL_TOOL_GROUPS_SKIPPED.append(f"{group} ({type(reason).__name__}: {reason})")


class RiskLevel(Enum):
    READ_ONLY = "read_only"
    MODIFIES_SYSTEM = "modifies_system"
    DESTRUCTIVE = "destructive"
    # Referenced by AutomatedGuardrailManager's critical-action tier. No tool is
    # registered at this level yet; it exists so that check does not raise.
    KERNEL_INTERVENTION = "kernel_intervention"

class ToolPermission(Enum):
    READ_ONLY = "READ_ONLY"
    REMEDIATE = "REMEDIATE"
    DESTRUCTIVE = "DESTRUCTIVE"


class CyberToolPlugin(ABC):
    """Base interface for tools dropped into the ``Tools_cyber`` directory.

    A plugin is adapted into the existing ``ToolDefinition`` registry, so the
    normal CyberAgent routing, guardrails, auditing, and UI events continue to
    apply to dynamically loaded tools.
    """

    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    environments: List[str] = ["cross_platform"]
    requires_admin: bool = False
    risk_level: RiskLevel = RiskLevel.READ_ONLY
    fallback_tool: Optional[str] = None

    @abstractmethod
    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the plugin and return a JSON-serializable result mapping."""
        raise NotImplementedError


class AuditLogger:
    """Logs all agent actions and tool calls for accountability and forensic auditing."""
    def __init__(self, log_path: str = "audit_log.json"):
        self.log_path = os.path.abspath(log_path)
        self._suppress = False
        if not os.path.exists(self.log_path):
            with open(self.log_path, "w", encoding="utf-8") as f:
                json.dump([], f)

    def suppress(self, flag: bool = True):
        self._suppress = flag

    def log_event(self, action: str, details: Dict[str, Any], status: str = "SUCCESS"):
        if self._suppress:
            return
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action,
            "details": details,
            "status": status
        }
        try:
            with open(self.log_path, "r+", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                except json.JSONDecodeError:
                    logs = []
                logs.append(entry)
                f.seek(0)
                json.dump(logs, f, indent=2)
                f.truncate()
        except Exception as e:
            print(f"[!] Audit log write error: {e}")

class GuardrailManager:
    """Manages safety checks and human-in-the-loop approvals for sensitive operations."""
    def __init__(self, auto_approve_read_only: bool = True, approval_callback: Optional[Callable[[str, str, Dict[str, Any]], bool]] = None):
        self.auto_approve_read_only = auto_approve_read_only
        # Set by a GUI front-end to prompt the operator. Without it the only
        # channel is input() on stdin, which does not exist under a GUI -- there
        # every approval fell through to EOFError and was silently denied, so no
        # remediation tool could ever be approved.
        self.approval_callback = approval_callback

    def set_approval_callback(self, callback: Optional[Callable[[str, str, Dict[str, Any]], bool]]) -> None:
        """Register a front-end approval prompt. Receives (action, risk_level, details)."""
        self.approval_callback = callback

    def request_approval(self, action_name: str, risk_level: RiskLevel, details: Dict[str, Any]) -> bool:
        if risk_level == RiskLevel.READ_ONLY and self.auto_approve_read_only:
            return True

        if self.approval_callback is not None:
            # A front-end that fails to answer must deny, never default to allow.
            try:
                return bool(self.approval_callback(action_name, risk_level.value, details))
            except Exception as exc:
                print(f"[!] Approval prompt failed, denying '{action_name}': {type(exc).__name__}: {exc}")
                return False

        print(f"\n[GUARDRAIL CONFIRMATION REQUIRED]")
        print(f"Action: {action_name}")
        print(f"Risk Level: {risk_level.value}")
        print(f"Details: {json.dumps(details, indent=2, default=str)}")

        if not sys.stdin or not sys.stdin.isatty():
            # No console to answer on. Deny, but say why -- "rejected by guardrail"
            # alone reads like a policy decision rather than a missing prompt.
            print(
                f"[!] '{action_name}' ({risk_level.value}) needs approval but no console is "
                "attached and no approval callback is registered. Denying."
            )
            return False
        try:
            user_input = input("Approve action execution? (y/N): ").strip().lower()
            return user_input in ['y', 'yes']
        except (EOFError, KeyboardInterrupt):
            return False

# --- 1. WSL Detection Layer ---

class WSLDetector:
    """Detects and caches WSL availability, installed distros, and default distro."""
    
    @staticmethod
    def detect_wsl(timeout: int = 5) -> Dict[str, Any]:
        result = {
            "wsl_available": False,
            "wsl_distros": [],
            "default_distro": "",
            "wsl_version": "Unknown"
        }
        
        wsl_path = shutil.which("wsl")
        if not wsl_path:
            return result

        try:
            # Check WSL status/version info
            status_proc = subprocess.run(
                [wsl_path, "--status"],
                capture_output=True,
                timeout=timeout
            )
            stdout_str = status_proc.stdout.decode('utf-16-le', errors='ignore') if status_proc.stdout else ""
            if status_proc.returncode == 0 or "Default Version" in stdout_str or "WSL" in stdout_str:
                result["wsl_available"] = True
                if "Default Version: 2" in stdout_str or "WSL 2" in stdout_str:
                    result["wsl_version"] = "WSL2"
                elif "Default Version: 1" in stdout_str or "WSL 1" in stdout_str:
                    result["wsl_version"] = "WSL1"

            list_proc = subprocess.run(
                [wsl_path, "-l", "-v"],
                capture_output=True,
                timeout=timeout
            )
            raw_out = list_proc.stdout or b""
            try:
                output = raw_out.decode('utf-16-le', errors='ignore')
            except Exception:
                output = raw_out.decode('utf-8', errors='ignore')

            if output:
                lines = [line.strip() for line in output.replace('\x00', '').splitlines() if line.strip()]
                distros = []
                for line in lines[1:]:  # Skip header line
                    is_default = "*" in line
                    cleaned = line.replace("*", "").strip()
                    parts = re.split(r'\s+', cleaned)
                    if parts and parts[0]:
                        distro_name = parts[0]
                        distros.append(distro_name)
                        if is_default or not result["default_distro"]:
                            result["default_distro"] = distro_name
                
                result["wsl_distros"] = distros
                if distros:
                    result["wsl_available"] = True

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return result

# --- 2. Tool Definition & Registry ---

class ToolDefinition:
    def __init__(
        self,
        name: str,
        environments: List[str],
        command_template: str,
        requires_admin: bool = False,
        risk_level: RiskLevel = RiskLevel.READ_ONLY,
        fallback_tool: Optional[str] = None,
        python_func: Optional[Callable] = None
    ):
        self.name = name
        self.environments = environments
        self.command_template = command_template
        self.requires_admin = requires_admin
        self.risk_level = risk_level
        self.fallback_tool = fallback_tool
        self.python_func = python_func

    def to_manifest(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": getattr(self, "description", self.name.replace("_", " ")),
            "environments": list(self.environments),
            "requires_admin": self.requires_admin,
            "risk_level": self.risk_level.value,
            "supports_python": self.python_func is not None,
            "has_command": bool(self.command_template),
            "version": getattr(self, "version", "1.0.0"),
            "is_dynamic_plugin": getattr(self, "plugin", None) is not None,
        }


def _run_dynamic_cyber_plugin(
    plugin: CyberToolPlugin, **arguments: Any
) -> Dict[str, Any]:
    """Adapt a plugin call to the existing ``CyberAgent`` function contract."""
    result = plugin.run(arguments)
    if not isinstance(result, dict):
        raise TypeError(
            f"plugin '{plugin.name}' must return a dictionary, "
            f"got {type(result).__name__}"
        )
    return result


def register_dynamic_cyber_tools(
    registry: "ToolRegistry", tools_directory: Optional[str] = None
) -> Dict[str, Any]:
    """Discover and register plugins from ``Tools_cyber``.

    Each non-private ``.py`` file is imported in isolation. A module must
    expose ``TOOL_CLASS`` pointing to a concrete ``CyberToolPlugin`` subclass.
    Import or validation failures are returned in ``errors`` and do not stop
    the rest of the tool catalog from loading.
    """
    directory = os.path.abspath(
        tools_directory
        or os.path.join(os.path.dirname(os.path.abspath(__file__)), "Tools_cyber")
    )
    summary: Dict[str, Any] = {"directory": directory, "loaded": [], "errors": {}}

    if not os.path.isdir(directory):
        summary["errors"]["<directory>"] = f"directory does not exist: {directory}"
        return summary

    for filename in sorted(os.listdir(directory)):
        if (
            filename.startswith("_")
            or not filename.endswith(".py")
            or filename == "__init__.py"
        ):
            continue

        module_path = os.path.join(directory, filename)
        module_name = f"_cybertools_plugin_{os.path.splitext(filename)[0]}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            if spec is None or spec.loader is None:
                raise ImportError(f"could not create import spec for {filename}")

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            plugin_class = getattr(module, "TOOL_CLASS", None)
            if not isinstance(plugin_class, type):
                # Not a plugin module (e.g. utility/template/standalone scripts).
                # Silently skip — these files are not expected to define TOOL_CLASS.
                continue
            if not issubclass(plugin_class, CyberToolPlugin):
                raise TypeError("TOOL_CLASS must inherit from CyberToolPlugin")

            plugin = plugin_class()
            if not isinstance(plugin.name, str) or not plugin.name.strip():
                raise ValueError("plugin name must be a non-empty string")
            if not isinstance(plugin.description, str) or not plugin.description.strip():
                raise ValueError(f"plugin '{plugin.name}' needs a description")
            if not isinstance(plugin.version, str) or not plugin.version.strip():
                raise ValueError(f"plugin '{plugin.name}' needs a version")
            if not isinstance(plugin.environments, (list, tuple)) or not all(
                isinstance(environment, str) and environment.strip()
                for environment in plugin.environments
            ):
                raise TypeError(
                    f"plugin '{plugin.name}' environments must be a list of strings"
                )
            if not isinstance(plugin.risk_level, RiskLevel):
                raise TypeError(
                    f"plugin '{plugin.name}' risk_level must be a RiskLevel"
                )
            if plugin.name in registry.tools:
                # Already registered (e.g. via direct registration above).
                # Silently skip to avoid duplicate registration errors.
                continue

            tool_definition = ToolDefinition(
                name=plugin.name,
                environments=list(plugin.environments),
                command_template="",
                requires_admin=plugin.requires_admin,
                risk_level=plugin.risk_level,
                fallback_tool=plugin.fallback_tool,
                python_func=lambda _plugin=plugin, **kwargs: _run_dynamic_cyber_plugin(
                    _plugin, **kwargs
                ),
            )
            tool_definition.description = plugin.description
            tool_definition.version = plugin.version
            tool_definition.plugin = plugin
            registry.register_tool(tool_definition)
            summary["loaded"].append(plugin.name)
        except Exception as exc:
            summary["errors"][filename] = f"{type(exc).__name__}: {exc}"
            sys.modules.pop(module_name, None)

    return summary


class ToolRegistry:
    """Maintains registered tools and performs conditional environment tool dispatching."""

    def __init__(self, audit_logger: AuditLogger, wsl_state: Optional[Dict[str, Any]] = None):
        self.tools: Dict[str, ToolDefinition] = {}
        self.audit_logger = audit_logger
        self.wsl_state = wsl_state or WSLDetector.detect_wsl()

    def register_tool(self, tool_def: ToolDefinition):
        self.tools[tool_def.name] = tool_def
        self.audit_logger.log_event(
            "tool_registered",
            {
                "name": tool_def.name,
                "environments": tool_def.environments,
                "risk_level": tool_def.risk_level.value
            }
        )

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return the complete registered tool catalog as manifests."""
        return [tool.to_manifest() for tool in self.tools.values()]

    def is_environment_available(self, env: str) -> bool:
        if env == "cross_platform":
            return True
        if env == "native_windows":
            return sys.platform == "win32"
        if env == "wsl_linux":
            return self.wsl_state.get("wsl_available", False)
        return False

    def dynamic_register_script(self, name: str, description: str, script_code: str, risk_level: RiskLevel = RiskLevel.READ_ONLY, version: str = "1.0.0") -> bool:
        """Dynamically validates AST and registers a Python script snippet as a tool."""
        try:
            ast.parse(script_code)
            scope = {}
            exec(script_code, scope)
            if name not in scope or not callable(scope[name]):
                raise ValueError(f"Script must define a callable function named '{name}'.")
            
            tool_def = ToolDefinition(
                name=name,
                environments=["cross_platform"],
                command_template="",
                risk_level=risk_level,
                python_func=scope[name]
            )
            self.register_tool(tool_def)
            return True
        except Exception as e:
            self.audit_logger.log_event("dynamic_registration_failed", {"name": name, "error": str(e)}, status="FAILED")
            print(f"[!] Tool Registration Error: {e}")
            return False

def _safe_workspace_path(root: str, candidate: str) -> str:
    base = os.path.abspath(root or ".")
    path = os.path.abspath(os.path.join(base, candidate)) if not os.path.isabs(candidate) else os.path.abspath(candidate)
    if os.path.commonpath([base, path]) != base:
        raise ValueError("Path is outside the configured workspace")
    return path


def _list_workspace_files(root: str = ".", pattern: str = "*", max_results: int = 200) -> Dict[str, Any]:
    base = os.path.abspath(root or ".")
    results = []
    for current_root, dirs, files in os.walk(base):
        dirs[:] = [name for name in dirs if name not in {".git", "__pycache__", "node_modules"} and not name.startswith(".")]
        for filename in files:
            if len(results) >= max(1, min(max_results, 1000)):
                return {"root": base, "pattern": pattern, "files": results, "truncated": True}
            if not __import__("fnmatch").fnmatch(filename, pattern):
                continue
            results.append(os.path.relpath(os.path.join(current_root, filename), base))
    return {"root": base, "pattern": pattern, "files": results, "truncated": False}


def _read_workspace_file(filepath: str = "", max_bytes: int = 200000) -> Dict[str, Any]:
    path = _safe_workspace_path(".", filepath)
    if not os.path.isfile(path):
        return {"error": f"File not found: {filepath}", "path": filepath}
    with open(path, "rb") as handle:
        content = handle.read(max(1, min(max_bytes, 1000000)))
    return {"path": filepath, "bytes": len(content), "content": content.decode("utf-8", errors="replace")}


def _list_available_drives() -> Dict[str, Any]:
    """Return the filesystem drives currently visible to this process."""
    drives = [
        f"{letter}:\\"
        for letter in string.ascii_uppercase
        if os.path.exists(f"{letter}:\\")
    ]
    return {"drives": drives, "count": len(drives)}


def register_all_default_tools(registry: ToolRegistry):
    """Registers the complete tool catalog into the specified ToolRegistry."""
    global _SKIP_SUMMARY_REPORTED
    registry.audit_logger.suppress(True)
    registry.register_tool(ToolDefinition(
        "workspace_list_files", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY,
        python_func=lambda root=".", pattern="*", max_results=200: _list_workspace_files(root, pattern, max_results),
    ))
    registry.register_tool(ToolDefinition(
        "workspace_read_file", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY,
        python_func=lambda filepath="", max_bytes=200000: _read_workspace_file(filepath, max_bytes),
    ))
    registry.register_tool(ToolDefinition(
        "list_available_drives", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY,
        python_func=_list_available_drives,
    ))
    # Python & Diagnostics
    registry.register_tool(ToolDefinition(
    name="static_analysis",
    environments=["cross_platform"],
    command_template="",
    risk_level=RiskLevel.READ_ONLY,
    python_func=StaticCodeAnalyzer.analyze_python_code
        ))
    registry.register_tool(ToolDefinition(
        name="network_inspect",
        environments=["cross_platform"],
        command_template="",
        risk_level=RiskLevel.READ_ONLY,
        python_func=SystemMonitor.inspect_active_connections
    ))

    # Fallback Pairs
    has_native_nmap = shutil.which("nmap") is not None
    if has_native_nmap:
        registry.register_tool(ToolDefinition("nmap_scan", ["native_windows"], "nmap {target}", risk_level=RiskLevel.READ_ONLY))
    else:
        registry.register_tool(ToolDefinition("nmap_scan", ["wsl_linux"], "nmap {target}", risk_level=RiskLevel.READ_ONLY))

    registry.register_tool(ToolDefinition("clamav_scan", ["wsl_linux"], "clamscan -r {target}", risk_level=RiskLevel.READ_ONLY, fallback_tool="windows_defender_scan"))
    defender_path = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")
    registry.register_tool(ToolDefinition("windows_defender_scan", ["native_windows"], f'& "{defender_path}" -Scan -ScanType 3 -File "{{target}}"', risk_level=RiskLevel.READ_ONLY))
    
    registry.register_tool(ToolDefinition("rkhunter_scan", ["wsl_linux"], "rkhunter --check --sk", risk_level=RiskLevel.READ_ONLY, fallback_tool="autoruns_scan"))
    registry.register_tool(ToolDefinition("autoruns_scan", ["native_windows"], "autorunsc64.exe -a * -ct", risk_level=RiskLevel.READ_ONLY))
    
    registry.register_tool(ToolDefinition("aide_check", ["wsl_linux"], "aide --check", risk_level=RiskLevel.READ_ONLY, fallback_tool="powershell_file_hash"))
    registry.register_tool(ToolDefinition("powershell_file_hash", ["native_windows"], "powershell -NoProfile -Command \"Get-ChildItem -Path '{target}' -Recurse | Get-FileHash\"", risk_level=RiskLevel.READ_ONLY))
    
    registry.register_tool(ToolDefinition("auditd_monitor", ["wsl_linux"], "ausearch -m execve", risk_level=RiskLevel.READ_ONLY, fallback_tool="windows_process_monitor"))
    registry.register_tool(ToolDefinition("windows_process_monitor", ["native_windows"], "powershell -NoProfile -Command \"Get-Process | Select-Object Id, ProcessName, Path\"", risk_level=RiskLevel.READ_ONLY))

    # Reconnaissance & Network Analysis
    registry.register_tool(ToolDefinition("tshark_capture", ["wsl_linux", "native_windows"], "tshark -i {interface} -c {count}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("netcat_test", ["wsl_linux", "native_windows"], "nc -zv {host} {port}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("masscan_scan", ["wsl_linux"], "masscan {target} -p{ports}", requires_admin=True, risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("arp_scan", ["wsl_linux"], "arp-scan --localnet", requires_admin=True, risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("netdiscover", ["wsl_linux"], "netdiscover -r {range}", requires_admin=True, risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("traceroute", ["wsl_linux", "native_windows"], "tracert {target}" if sys.platform == "win32" else "traceroute {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("ping", ["cross_platform"], "ping -c 4 {target}" if sys.platform != "win32" else "ping -n 4 {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("nslookup", ["cross_platform"], "nslookup {domain}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("dig", ["wsl_linux"], "dig {domain}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("nikto", ["wsl_linux"], "nikto -h {target}", risk_level=RiskLevel.READ_ONLY))

    # Vulnerability & Malware Scanning
    registry.register_tool(ToolDefinition("yara_scan", ["wsl_linux", "native_windows"], "yara {rules} {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("osv_scanner", ["cross_platform"], "osv-scanner -r {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("grype_scan", ["cross_platform"], "grype {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("trivy_scan", ["cross_platform"], "trivy fs {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("openvas_scan", ["wsl_linux"], "gvm-cli socket --xml '<get_tasks/>'", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("virustotal_scan", ["cross_platform"], "vt file {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("chkrootkit_scan", ["wsl_linux"], "chkrootkit", requires_admin=True, risk_level=RiskLevel.READ_ONLY))

    # Static & Dynamic Code Analysis
    registry.register_tool(ToolDefinition("bandit_scan", ["cross_platform"], "bandit -r {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("semgrep_scan", ["cross_platform"], "semgrep --config p/security-audit {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("codeql_analyze", ["cross_platform"], "codeql database analyze {db} --format=sarif-latest --output={output}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("eslint_security", ["cross_platform"], "npx eslint {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("pylint_check", ["cross_platform"], "pylint {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("flake8_check", ["cross_platform"], "flake8 {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("cppcheck_scan", ["cross_platform"], "cppcheck --enable=all {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("gosec_scan", ["cross_platform"], "gosec ./...", risk_level=RiskLevel.READ_ONLY))

    # File & System Integrity
    registry.register_tool(ToolDefinition("tripwire_check", ["wsl_linux"], "tripwire --check", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("sha256sum", ["cross_platform"], "sha256sum {target}" if sys.platform != "win32" else "powershell -Command \"Get-FileHash '{target}'\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("hashdeep", ["wsl_linux"], "hashdeep -r {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("sysmon_query", ["native_windows"], "powershell -Command \"Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 50\"", risk_level=RiskLevel.READ_ONLY))

    # Forensics & Incident Response
    registry.register_tool(ToolDefinition("volatility_memory", ["cross_platform"], "vol -f {image} {plugin}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("sleuthkit_fls", ["cross_platform"], "fls {image}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("plaso_log2timeline", ["wsl_linux"], "log2timeline.py {output} {image}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("strings_inspect", ["cross_platform"], "strings {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("exiftool_inspect", ["cross_platform"], "exiftool {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("binwalk_inspect", ["wsl_linux"], "binwalk {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("capa_detect", ["cross_platform"], "capa {target}", risk_level=RiskLevel.READ_ONLY))

    # Pentesting / Authorized Testing Tools
    registry.register_tool(ToolDefinition("metasploit_console", ["wsl_linux"], "msfconsole -q -x '{command}'", risk_level=RiskLevel.DESTRUCTIVE))
    registry.register_tool(ToolDefinition("zap_cli_scan", ["cross_platform"], "zap-cli quick-scan --self-contained {target}", risk_level=RiskLevel.MODIFIES_SYSTEM))
    registry.register_tool(ToolDefinition("sqlmap_scan", ["cross_platform"], "sqlmap -u '{url}' --batch", risk_level=RiskLevel.MODIFIES_SYSTEM))
    registry.register_tool(ToolDefinition("hydra_test", ["wsl_linux"], "hydra -l {user} -P {passlist} {target} {service}", risk_level=RiskLevel.MODIFIES_SYSTEM))

    # Windows Native Cmdlets & Utilities
    registry.register_tool(ToolDefinition("get_winevent", ["native_windows"], "powershell -Command \"Get-WinEvent -LogName '{log_name}' -MaxEvents 20\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("get_service", ["native_windows"], "powershell -Command \"Get-Service\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("psscriptanalyzer", ["native_windows"], "powershell -Command \"Invoke-ScriptAnalyzer -Path '{target}'\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("wmic_query", ["native_windows"], "wmic {alias} get {properties}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("netsh_query", ["native_windows"], "netsh interface show interface", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("sc_query", ["native_windows"], "sc query {service}", risk_level=RiskLevel.READ_ONLY))

    # Additional Defensive Tools from Untitled-1.py
    registry.register_tool(ToolDefinition("secret_scan", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=SecretScanner.scan_text_for_secrets))
    registry.register_tool(ToolDefinition("dependency_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=DependencyAnalyzer.check_python_requirements))
    registry.register_tool(ToolDefinition("terminate_process", ["cross_platform"], "", risk_level=RiskLevel.DESTRUCTIVE, python_func=ProcessManager.terminate_process_by_pid))
    registry.register_tool(ToolDefinition("block_ip", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=FirewallManager.block_ip_address))

    # KeyManager AI Integrated Tools (selective use)
    registry.register_tool(ToolDefinition("ai_secure_fix", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AiSecurityAssistant.generate_ai_fix))
    registry.register_tool(ToolDefinition("ai_incident_summary", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AiSecurityAssistant.generate_incident_summary))
    registry.register_tool(ToolDefinition("ai_yara_generator", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AiSecurityAssistant.generate_yara_rule))
    registry.register_tool(ToolDefinition("ai_triage_correlate", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AITriageEngine.correlate_findings))
    registry.register_tool(ToolDefinition("ai_explain_risk", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AICodeRiskExplainer.explain_code_risk))
    registry.register_tool(ToolDefinition("ai_anomaly_baseline", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AIAnomalyBaseline.check_baseline_anomaly))

    # Threat Intelligence / Reputation
    registry.register_tool(ToolDefinition("virustotal_hash_lookup", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ThreatIntel.vt_hash_lookup))
    registry.register_tool(ToolDefinition("urlscan_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ThreatIntel.urlscan_lookup))
    registry.register_tool(ToolDefinition("abuseipdb_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ThreatIntel.check_ip_reputation))
    registry.register_tool(ToolDefinition("shodan_lookup", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ThreatIntel.shodan_host_lookup))

    # Behavioral Detection
    registry.register_tool(ToolDefinition("sigma_rule_match", ["native_windows"], "", risk_level=RiskLevel.READ_ONLY, python_func=BehaviorDetector.match_sigma_rules))
    registry.register_tool(ToolDefinition("process_tree_analysis", ["native_windows"], "powershell -Command \"Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("suspicious_parent_child", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=BehaviorDetector.flag_suspicious_process_chains))

    # PE / Binary Analysis
    registry.register_tool(ToolDefinition("pe_header_analysis", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=BinaryAnalyzer.analyze_pe_headers))
    registry.register_tool(ToolDefinition("entropy_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=BinaryAnalyzer.calculate_entropy))
    registry.register_tool(ToolDefinition("import_table_scan", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=BinaryAnalyzer.flag_suspicious_imports))

    # Network Deep Inspection
    registry.register_tool(ToolDefinition("dns_exfil_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=NetworkAnalyzer.detect_dns_tunneling))
    registry.register_tool(ToolDefinition("beaconing_detect", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=NetworkAnalyzer.detect_periodic_callbacks))
    registry.register_tool(ToolDefinition("tls_cert_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=NetworkAnalyzer.inspect_tls_certificate))

    # Phishing & Social Engineering Detection
    registry.register_tool(ToolDefinition("email_header_analysis", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=PhishDetector.analyze_email_headers))
    registry.register_tool(ToolDefinition("url_similarity_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=PhishDetector.detect_typosquat))
    registry.register_tool(ToolDefinition("attachment_macro_scan", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=PhishDetector.scan_office_macros))

    # Compliance & Config Auditing
    registry.register_tool(ToolDefinition("cis_benchmark_check", ["native_windows"], "", risk_level=RiskLevel.READ_ONLY, python_func=ComplianceAuditor.run_cis_checks))
    registry.register_tool(ToolDefinition("firewall_rule_audit", ["native_windows"], "powershell -Command \"Get-NetFirewallRule | Where Enabled -eq True\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("open_port_audit", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ComplianceAuditor.audit_listening_ports))
    registry.register_tool(ToolDefinition("password_policy_check", ["native_windows"], "powershell -Command \"net accounts\"", risk_level=RiskLevel.READ_ONLY))

    # Remediation (Gated under MODIFIES_SYSTEM / DESTRUCTIVE)
    registry.register_tool(ToolDefinition("quarantine_file", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=RemediationManager.quarantine_file))
    registry.register_tool(ToolDefinition("disable_startup_entry", ["native_windows"], "", risk_level=RiskLevel.DESTRUCTIVE, python_func=RemediationManager.disable_autorun_entry))
    registry.register_tool(ToolDefinition("revert_registry_key", ["native_windows"], "", risk_level=RiskLevel.DESTRUCTIVE, python_func=RemediationManager.rollback_registry_key))
    registry.register_tool(ToolDefinition("kill_and_block", ["cross_platform"], "", risk_level=RiskLevel.DESTRUCTIVE, python_func=RemediationManager.terminate_and_isolate))

    # Report Generation
    registry.register_tool(ToolDefinition("generate_incident_report", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ReportGenerator.build_incident_summary))

    # Generic Shell Execution (PowerShell / WSL / CMD)
    try:
        from Tools_cyber.shell_exec import ShellExecTool
        _shell_exec = ShellExecTool()
        registry.register_tool(ToolDefinition(
            name=_shell_exec.name,
            environments=list(_shell_exec.environments),
            command_template="",
            requires_admin=_shell_exec.requires_admin,
            risk_level=_shell_exec.risk_level,
            fallback_tool=_shell_exec.fallback_tool,
            python_func=lambda **kwargs: _shell_exec.run(kwargs),
        ))
    except Exception as exc:
        _skip_optional_tool_group('shell_exec (Tools_cyber.shell_exec)', exc)


# --- Additional Defensive Security Tools (from Untitled-1.py) ---

class SecretScanner:
    """Detects leaked credentials, private keys, and API tokens across text files."""
    
    @staticmethod
    def scan_text_for_secrets(content: str) -> List[Dict[str, Any]]:
        patterns = [
            (r'-----BEGIN PRIVATE KEY-----', "RSA/ECC Private Key"),
            (r'xox[bap]-[0-9a-zA-Z]{10,48}', "Slack API Token"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID")
        ]
        leaks = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            for pattern, secret_type in patterns:
                if re.search(pattern, line):
                    leaks.append({
                        "line": line_num,
                        "type": secret_type,
                        "severity": "CRITICAL"
                    })
        return leaks

class RealtimeSecurityDaemon:
    """Continuously monitors system processes and active connections in background threads."""
    def __init__(self, agent):
        self.agent = agent
        self.running = False

    def start_monitoring(self, interval=3):
        self.running = True
        threading.Thread(target=self._process_loop, args=(interval,), daemon=True).start()

    def _process_loop(self, interval):
        while self.running:
            # Poll system connections using SystemMonitor
            connections = SystemMonitor.inspect_active_connections() #
            for conn in connections: #
                # Auto-block malicious remote endpoints automatically
                if self._is_blacklisted_ip(conn.get("foreign_addr", "")): #
                    print(f"[!] Threat Detected: Suspect IP {conn['foreign_addr']}. Triggering isolation.") #
                    self.agent.execute_tool("block_ip", {"ip_address": conn["foreign_addr"].split(":")[0]}) #
                    if conn.get("pid") and conn["pid"] != "0": #
                        self.agent.execute_tool("terminate_process", {"pid": int(conn["pid"])}) #[cite: 1, 2]
            time.sleep(interval)

    def _is_blacklisted_ip(self, remote_addr: str) -> bool:
        return "192.168.1.250" in remote_addr

class AutomatedGuardrailManager(GuardrailManager):
    """Extends GuardrailManager with non-interactive automated policy execution."""
    def __init__(self, auto_approve_read_only: bool = True, auto_remediate_critical: bool = True,
                 approval_callback: Optional[Callable[[str, str, Dict[str, Any]], bool]] = None):
        super().__init__(auto_approve_read_only=auto_approve_read_only, approval_callback=approval_callback)
        self.auto_remediate_critical = auto_remediate_critical

    def request_approval(self, action_name: str, risk_level: RiskLevel, details: Dict[str, Any]) -> bool:
        if risk_level == RiskLevel.READ_ONLY and self.auto_approve_read_only:
            return True

        if self.auto_remediate_critical and risk_level in [RiskLevel.MODIFIES_SYSTEM, RiskLevel.DESTRUCTIVE, RiskLevel.KERNEL_INTERVENTION]:
            if details.get("threat_score", 0) >= 8:
                print(f"[AUTO-POLICY] Auto-approving critical action: {action_name}")
                return True

        return super().request_approval(action_name, risk_level, details)


class KernelPrivilegeValidator:
    @staticmethod
    def is_privileged() -> bool:
        if sys.platform == "win32":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0


class HardwareIntegrityMonitor:
    @staticmethod
    def sha256_stream(filepath: str) -> Optional[str]:
        if not os.path.isfile(filepath):
            return None
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(65536):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    @classmethod
    def verify_memory_and_disk_alignment(cls, base_dir: str, baseline: Dict[str, str]) -> Dict[str, List[str]]:
        drift = {"modified": [], "added": [], "deleted": []}
        current_catalog = {}

        for root, _, files in os.walk(base_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, base_dir)
                digest = cls.sha256_stream(full_path)
                if digest:
                    current_catalog[rel_path] = digest

        for rel_path, orig_hash in baseline.items():
            if rel_path not in current_catalog:
                drift["deleted"].append(rel_path)
            elif current_catalog[rel_path] != orig_hash:
                drift["modified"].append(rel_path)

        for rel_path in current_catalog:
            if rel_path not in baseline:
                drift["added"].append(rel_path)

        return drift


class PlatformNativeTelemetry:
    @staticmethod
    def inspect_active_telemetry() -> List[Dict[str, str]]:
        connections = []
        if sys.platform == "win32":
            cmd = "netstat -ano -p tcp"
        else:
            cmd = "ss -tunp" if shutil.which("ss") else "netstat -tunp"

        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 4 and any(proto in parts[0].upper() for proto in ["TCP", "UDP"]):
                        connections.append({
                            "proto": parts[0],
                            "local_addr": parts[1],
                            "foreign_addr": parts[2],
                            "state": parts[3] if "TCP" in parts[0].upper() and len(parts) > 4 else "ESTABLISHED",
                            "pid": parts[-1].split("/")[-1] if "/" in parts[-1] else parts[-1]
                        })
        except Exception:
            pass
        return connections


class KernelInterceptionDaemon:
    def __init__(self, agent_orchestrator):
        self.orchestrator = agent_orchestrator
        self.is_running = False
        self.blacklisted_endpoints = {"192.168.1.250", "10.0.0.66", "185.220.101.5"}

    def start(self, poll_interval: float = 1.0):
        self.is_running = True
        self._executor = threading.Thread(target=self._telemetry_loop, args=(poll_interval,), daemon=True)
        self._executor.start()
        print("[+] Kernel Interception Daemon initialized [Mode: Event-Driven telemetry].")

    def stop(self):
        self.is_running = False

    def _telemetry_loop(self, interval: float):
        while self.is_running:
            connections = PlatformNativeTelemetry.inspect_active_telemetry()
            for conn in connections:
                foreign_ip = conn["foreign_addr"].split(":")[0] if ":" in conn["foreign_addr"] else conn["foreign_addr"]
                if foreign_ip in self.blacklisted_endpoints:
                    pid = int(conn["pid"]) if conn["pid"].isdigit() else 0
                    print(f"\n[!] [RING-0 ALERT] Malicious Socket Activity: {foreign_ip} (PID: {pid})")
                    self.orchestrator.execute_tool("block_ip", {"ip_address": foreign_ip}, threat_score=10)
                    if pid > 0:
                        self.orchestrator.execute_tool("terminate_process", {"pid": pid}, threat_score=10)
            time.sleep(interval)


class DependencyAnalyzer:
    """Audits local package dependencies for insecure or outdated requirements."""
    
    @staticmethod
    def check_python_requirements(requirements_path: str = "requirements.txt") -> Dict[str, Any]:
        if not os.path.exists(requirements_path):
            return {"error": f"Requirements file '{requirements_path}' not found."}
        
        with open(requirements_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        unpinned = []
        for idx, line in enumerate(lines, start=1):
            cleaned = line.strip()
            if cleaned and not cleaned.startswith("#"):
                if "==" not in cleaned:
                    unpinned.append({"line": idx, "package": cleaned})

        return {
            "total_dependencies": len(lines),
            "unpinned_dependencies": unpinned
        }

class ProcessManager:
    """Manages system process analysis and remediation."""

    @staticmethod
    def terminate_process_by_pid(pid: int) -> Dict[str, Any]:
        """Safely terminates a targeted process ID via system commands."""
        cmd = f"taskkill /F /PID {pid}" if sys.platform == "win32" else f"kill -9 {pid}"
        return execute_system_command(cmd, environment="cmd" if sys.platform == "win32" else "wsl")

    @staticmethod
    def identify_high_cpu_processes(threshold: float = 90.0) -> Dict[str, Any]:
        if sys.platform != "win32":
            return {"error": "Only supported on Windows"}
        cmd = "powershell -NoProfile -Command \"Get-Process | Where-Object CPU -gt $threshold | Select-Object Id, ProcessName, CPU\""
        res = execute_system_command(cmd)
        return {"output": res.get("stdout", ""), "error": res.get("error", "")}

    @staticmethod
    def detect_unusual_memory_hogs(threshold_mb: int = 2048) -> Dict[str, Any]:
        if sys.platform != "win32":
            return {"error": "Only supported on Windows"}
        cmd = "powershell -NoProfile -Command \"Get-Process | Where-Object WorkingSet -gt $threshold | Select-Object Id, ProcessName, @{N='MemoryMB';E={[math]::Round($_.WorkingSet/1MB)}}\""
        res = execute_system_command(cmd)
        return {"output": res.get("stdout", ""), "error": res.get("error", "")}

    @staticmethod
    def audit_hidden_background_services() -> Dict[str, Any]:
        if sys.platform != "win32":
            return {"error": "Only supported on Windows"}
        cmd = "powershell -NoProfile -Command \"Get-Service | Where-Object {$_.Status -eq 'Running' -and $_.DisplayName -notlike '*Windows*'} | Select-Object Name, DisplayName, Status\""
        res = execute_system_command(cmd)
        return {"output": res.get("stdout", ""), "error": res.get("error", "")}

class FirewallManager:
    """Applies network level mitigation and IP isolation rules."""

    @staticmethod
    def block_ip_address(ip_address: str) -> Dict[str, Any]:
        """Blocks inbound traffic from a suspicious IP address."""
        if sys.platform == "win32":
            cmd = f'netsh advfirewall firewall add rule name="Block_{ip_address}" dir=in action=block remoteip={ip_address}'
        else:
            cmd = f'iptables -A INPUT -s {ip_address} -j DROP'
        return execute_system_command(cmd, environment="cmd" if sys.platform == "win32" else "wsl")

class AiSecurityAssistant:
    """Selectively leverages KeyManager (I:\\it talent hunt\\key_manager.py) for AI-driven security analysis."""

    @staticmethod
    def _get_api():
        if KEY_MANAGER_AVAILABLE and AiApi is not None:
            try:
                return AiApi(use_mock=True)
            except Exception:
                return None
        return None

    @staticmethod
    def generate_ai_fix(vulnerability_desc: str, code_snippet: str) -> Dict[str, Any]:
        """Generates intelligent secure refactored code using KeyManager's coder role."""
        api = AiSecurityAssistant._get_api()
        if not api:
            return {"error": "KeyManager AiApi unavailable. Falling back to static fix rules."}
        
        system = "You are a senior security engineer. Provide only secure replacement code for the vulnerability."
        user = f"Vulnerability: {vulnerability_desc}\n\nCode Snippet:\n{code_snippet}"
        try:
            res = api.chat_with_role("coder", system, user)
            return {"status": "SUCCESS", "suggested_fix": res.choices[0].message.content}
        except Exception as e:
            return {"error": f"AI key execution failed: {e}"}

    @staticmethod
    def generate_incident_summary(events_json: str) -> Dict[str, Any]:
        """Synthesizes security audit events into an executive incident summary using analyst role."""
        api = AiSecurityAssistant._get_api()
        if not api:
            return {"error": "KeyManager AiApi unavailable."}
        
        system = "You are a SOC Incident Commander. Synthesize event log data into a concise incident report."
        user = f"Audit Events:\n{events_json}"
        try:
            res = api.chat_with_role("analyst", system, user)
            return {"status": "SUCCESS", "report": res.choices[0].message.content}
        except Exception as e:
            return {"error": f"AI key execution failed: {e}"}

    @staticmethod
    def generate_yara_rule(sample_description: str) -> Dict[str, Any]:
        """Generates YARA detection rule based on sample characteristics."""
        api = AiSecurityAssistant._get_api()
        if not api:
            return {"error": "KeyManager AiApi unavailable."}
        
        system = "You are a malware analyst. Write a valid YARA rule based on the threat description."
        user = f"Threat Description: {sample_description}"
        try:
            res = api.chat_with_role("analyst", system, user)
            return {"status": "SUCCESS", "yara_rule": res.choices[0].message.content}
        except Exception as e:
            return {"error": f"AI key execution failed: {e}"}


class AITriageEngine:
    """Correlates multi-tool scan findings into prioritized threat triage."""
    @staticmethod
    def correlate_findings(scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        total_findings = 0
        high_severity = 0
        medium_severity = 0
        low_severity = 0
        
        for result in scan_results:
            findings = result.get("findings", [])
            total_findings += len(findings)
            for f in findings:
                sev = f.get("severity", "").upper()
                if sev in ["CRITICAL", "HIGH"]:
                    high_severity += 1
                elif sev == "MEDIUM":
                    medium_severity += 1
                else:
                    low_severity += 1
        
        threat_score = min(10, high_severity * 2 + medium_severity)
        
        return {
            "total_findings": total_findings,
            "high_severity": high_severity,
            "medium_severity": medium_severity,
            "low_severity": low_severity,
            "threat_score": threat_score,
            "verdict": "CRITICAL" if threat_score >= 8 else "HIGH" if threat_score >= 5 else "MEDIUM" if threat_score >= 2 else "LOW",
            "recommendation": "Immediate action required" if threat_score >= 8 else "Review and remediate" if threat_score >= 5 else "Monitor closely" if threat_score >= 2 else "No immediate action needed"
        }


class AICodeRiskExplainer:
    """Explains code risks in plain language."""
    @staticmethod
    def explain_code_risk(finding: Dict[str, Any], code_line: str) -> str:
        risk_type = finding.get("type", "Unknown")
        severity = finding.get("severity", "UNKNOWN")
        message = finding.get("message", "")
        
        explanations = {
            "Dangerous Function": "This code uses eval() or exec(), which can execute arbitrary Python code. An attacker who can influence the input could run malicious code on your system.",
            "Command Injection Risk": "This code passes user input to os.system() or subprocess without proper sanitization. An attacker could inject additional shell commands.",
            "Hardcoded Secret Risk": "This line contains what appears to be a hardcoded credential. If this code is exposed, the secret is compromised.",
            "Syntax Error": "This code has a syntax error and will not run. Fix the syntax before deploying."
        }
        
        return explanations.get(risk_type, f"{severity} risk: {message}")


class AIAnomalyBaseline:
    """Detects anomalies against baseline network behavior."""
    @staticmethod
    def check_baseline_anomaly(current_connections: List[Dict[str, Any]], baseline_ports: List[int]) -> Dict[str, Any]:
        anomalies = []
        for conn in current_connections:
            foreign = conn.get("foreign_addr", "")
            port = int(foreign.split(":")[1]) if ":" in foreign else 0
            if port and port not in baseline_ports:
                anomalies.append({
                    "connection": conn,
                    "reason": f"Port {port} is not in baseline ports {baseline_ports}",
                    "severity": "HIGH" if port < 1024 else "MEDIUM"
                })
        
        return {
            "total_connections": len(current_connections),
            "baseline_ports": baseline_ports,
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
            "is_anomalous": len(anomalies) > 0
        }


class ThreatIntel:
    """Threat intelligence lookups.

    VirusTotal and AlienVault OTX are backed by cyber_threat_intel.ThreatIntelManager
    and make real API calls when the corresponding key is set. URLScan, AbuseIPDB and
    Shodan have no implementation yet.

    Every method that cannot produce a real answer returns verdict="unknown". None of
    them ever returns a clean-looking result for a lookup that did not happen — a
    false-negative here would tell the agent a malicious artifact is safe.
    """

    _manager = None

    @staticmethod
    def _get_manager():
        """Lazily construct the shared manager so keys are read at call time, not import time."""
        if not THREAT_INTEL_AVAILABLE:
            return None
        if ThreatIntel._manager is None:
            ThreatIntel._manager = ThreatIntelManager()
        return ThreatIntel._manager

    @staticmethod
    def _unavailable(reason: str, **extra: Any) -> Dict[str, Any]:
        return {"status": "not_implemented", "verdict": "unknown", "message": reason, **extra}

    @staticmethod
    def vt_hash_lookup(file_hash: str) -> Dict[str, Any]:
        """Look up a file hash on VirusTotal. Discloses the hash to VirusTotal."""
        manager = ThreatIntel._get_manager()
        if manager is None:
            return ThreatIntel._unavailable(
                "cyber_threat_intel module is unavailable.", hash=file_hash
            )
        return manager.lookup_hash_virustotal(file_hash)

    @staticmethod
    def vt_ip_lookup(ip_address: str) -> Dict[str, Any]:
        """Look up an IP address on VirusTotal. Discloses the IP to VirusTotal."""
        manager = ThreatIntel._get_manager()
        if manager is None:
            return ThreatIntel._unavailable(
                "cyber_threat_intel module is unavailable.", ip=ip_address
            )
        return manager.lookup_ip_virustotal(ip_address)

    @staticmethod
    def otx_ip_lookup(ip_address: str) -> Dict[str, Any]:
        """Look up an IP address on AlienVault OTX. Discloses the IP to OTX."""
        manager = ThreatIntel._get_manager()
        if manager is None:
            return ThreatIntel._unavailable(
                "cyber_threat_intel module is unavailable.", ip=ip_address
            )
        return manager.lookup_ip_otx(ip_address)

    @staticmethod
    def enrich_artifact(artifact_type: str, value: str) -> Dict[str, Any]:
        """Enrich an 'ip' or 'hash' across every configured provider at once."""
        manager = ThreatIntel._get_manager()
        if manager is None:
            return ThreatIntel._unavailable(
                "cyber_threat_intel module is unavailable.",
                artifact=value,
                type=artifact_type,
            )
        return manager.enrich_artifact(artifact_type, value)

    @staticmethod
    def urlscan_lookup(url: str) -> Dict[str, Any]:
        return ThreatIntel._unavailable(
            "URLScan lookup is not implemented; no scan was performed.", url=url
        )

    @staticmethod
    def check_ip_reputation(ip_address: str) -> Dict[str, Any]:
        # Deliberately NOT routed to VirusTotal: this backs the `abuseipdb_check` tool,
        # and serving VT data from a tool named after AbuseIPDB would misreport the source.
        # Use virustotal_ip_lookup or otx_ip_lookup for real IP reputation.
        return ThreatIntel._unavailable(
            "AbuseIPDB lookup is not implemented; no reputation data was retrieved. "
            "Use virustotal_ip_lookup or otx_ip_lookup instead.",
            ip=ip_address,
        )

    @staticmethod
    def shodan_host_lookup(ip: str) -> Dict[str, Any]:
        return ThreatIntel._unavailable(
            "Shodan lookup is not implemented; no host data was retrieved.", ip=ip
        )


class BehaviorDetector:
    """Behavioral analysis and suspicious process chain detection."""
    @staticmethod
    def match_sigma_rules(log_name: str) -> Dict[str, Any]:
        return {"status": "simulated", "log_name": log_name, "matches": []}
    
    @staticmethod
    def flag_suspicious_process_chains() -> Dict[str, Any]:
        return {"status": "simulated", "suspicious_chains": []}


class BinaryAnalyzer:
    """Binary/PE file analysis and entropy detection."""
    @staticmethod
    def analyze_pe_headers(filepath: str) -> Dict[str, Any]:
        return {"status": "simulated", "filepath": filepath, "pe_info": {}}
    
    @staticmethod
    def calculate_entropy(filepath: str) -> Dict[str, Any]:
        import math
        if not os.path.exists(filepath):
            return {"error": f"File not found: {filepath}"}
        
        with open(filepath, "rb") as f:
            data = f.read()
        
        if not data:
            return {"entropy": 0.0, "assessment": "Empty file"}
        
        entropy = 0.0
        for byte_val in range(256):
            p_x = data.count(bytes([byte_val])) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        
        assessment = "High entropy (possibly encrypted/packed)" if entropy > 7.0 else "Medium entropy" if entropy > 5.0 else "Low entropy (likely plaintext)"
        
        return {
            "filepath": filepath,
            "entropy": round(entropy, 4),
            "assessment": assessment
        }
    
    @staticmethod
    def flag_suspicious_imports(filepath: str) -> Dict[str, Any]:
        return {"status": "simulated", "filepath": filepath, "suspicious_imports": []}


class NetworkAnalyzer:
    """Network traffic analysis for exfiltration and beaconing."""
    @staticmethod
    def detect_dns_tunneling() -> Dict[str, Any]:
        return {"status": "simulated", "dns_tunneling_detected": False}
    
    @staticmethod
    def detect_periodic_callbacks() -> Dict[str, Any]:
        return {"status": "simulated", "beaconing_detected": False}
    
    @staticmethod
    def inspect_tls_certificate(host: str) -> Dict[str, Any]:
        return {"status": "simulated", "host": host, "cert_valid": True}


class PhishDetector:
    """Phishing and social engineering detection."""
    @staticmethod
    def analyze_email_headers(headers: str) -> Dict[str, Any]:
        return {"status": "simulated", "suspicious": False}
    
    @staticmethod
    def detect_typosquat(domain: str, known_domains: List[str]) -> Dict[str, Any]:
        import difflib
        
        results = []
        for known in known_domains:
            ratio = difflib.SequenceMatcher(None, domain.lower(), known.lower()).ratio()
            if ratio > 0.7 and domain.lower() != known.lower():
                results.append({
                    "known_domain": known,
                    "similarity": round(ratio * 100, 1),
                    "risk": "HIGH" if ratio > 0.9 else "MEDIUM"
                })
        
        is_suspicious = len(results) > 0
        return {
            "domain": domain,
            "is_suspicious": is_suspicious,
            "matches": results,
            "verdict": "TYPOSQUAT DETECTED" if is_suspicious else "CLEAN"
        }
    
    @staticmethod
    def scan_office_macros(filepath: str) -> Dict[str, Any]:
        return {"status": "simulated", "filepath": filepath, "macros_found": False}


class ComplianceAuditor:
    """Compliance and configuration auditing."""
    @staticmethod
    def run_cis_checks() -> Dict[str, Any]:
        return {"status": "simulated", "cis_score": "N/A", "failures": []}
    
    @staticmethod
    def audit_listening_ports() -> Dict[str, Any]:
        return {"status": "simulated", "open_ports": [], "unexpected": []}


class RemediationManager:
    """Automated remediation actions."""
    @staticmethod
    def quarantine_file(filepath: str) -> Dict[str, Any]:
        normalized = filepath.replace("/", "\\").lower()
        if normalized.startswith("f:\\") or normalized.startswith("h:\\"):
            return {"status": "error", "error": f"Cannot quarantine file: {filepath} is on a protected read-only drive."}
        return {"status": "simulated", "action": "quarantine", "filepath": filepath}
    
    @staticmethod
    def disable_autorun_entry(entry_name: str) -> Dict[str, Any]:
        return {"status": "simulated", "action": "disable_autorun", "entry": entry_name}
    
    @staticmethod
    def rollback_registry_key(key_path: str) -> Dict[str, Any]:
        return {"status": "simulated", "action": "rollback", "key": key_path}
    
    @staticmethod
    def terminate_and_isolate(pid: int, ip_address: str = None) -> Dict[str, Any]:
        return {"status": "simulated", "action": "kill_and_block", "pid": pid, "ip": ip_address}


class ReportGenerator:
    """Incident report generation."""
    @staticmethod
    def build_incident_summary(events: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "status": "simulated",
            "report": "Incident summary generated from audit logs.",
            "events_analyzed": len(events),
            "critical_events": sum(1 for e in events if e.get("status") == "DENIED")
        }

# --- Built-in Helper Tools & Analysis ---

def execute_system_command(command: str, environment: str = "cmd", timeout: Optional[int] = 15, output_callback: Optional[Callable[[str], None]] = None, cancel_event: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Executes commands safely in CMD, PowerShell, or WSL environments."""
    # Defense-in-depth: enforce read-only protection for protected drives (F:\, H:\)
    cmd_lower = command.lower()
    for protected in ("f:\\", "f:/", "h:\\", "h:/", "/mnt/f", "/mnt/h"):
        if protected in cmd_lower:
            mutating_ops = ["rm ", "del ", "remove-item", "erase ", "format ", ">", "out-file", "set-content", "add-content"]
            if any(op in cmd_lower for op in mutating_ops):
                return {
                    "error": f"Operation denied: Path on protected drive ({protected[:2].upper()}) is read-only.",
                    "returncode": 1
                }

    env_lower = environment.lower()
    if env_lower == "cmd":
        cmd_args = ["cmd.exe", "/c", command]
    elif env_lower == "powershell":
        cmd_args = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command]
    elif env_lower == "wsl":
        cmd_args = ["wsl.exe", "bash", "-c", command]
    else:
        return {"error": f"Unsupported environment: {environment}"}

    try:
        if output_callback is not None or cancel_event is not None:
            proc = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            output_lines = []
            assert proc.stdout is not None
            for line in proc.stdout:
                if cancel_event is not None and cancel_event.is_set():
                    proc.terminate()
                    proc.wait(timeout=5)
                    return {"stdout": "".join(output_lines), "stderr": "", "returncode": -15, "cancelled": True}
                output_lines.append(line)
                if output_callback is not None:
                    output_callback(line.rstrip())
            proc.wait(timeout=timeout)
            return {
                "stdout": "".join(output_lines),
                "stderr": "",
                "returncode": proc.returncode,
            }

        proc = subprocess.run(cmd_args, capture_output=True, text=True, timeout=timeout)
        return {
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "returncode": proc.returncode
        }
    except subprocess.TimeoutExpired:
        return {"error": "Execution timed out"}
    except Exception as e:
        return {"error": str(e)}


class SelfFixingCodeEngine:
    @staticmethod
    def auto_patch_and_replace(filepath: str) -> bool:
        if not os.path.exists(filepath):
            return False
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()
        try:
            parsed = ast.parse(code)
            class SecurityTransformer(ast.NodeTransformer):
                def visit_Call(self, node):
                    if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
                        print(f"[AUTO-PATCH] Neutralized dangerous function '{node.func.id}()' on line {node.lineno}")
                        return ast.Constant(value=None)
                    return self.generic_visit(node)
            transformed = SecurityTransformer().visit(parsed)
            ast.fix_missing_locations(transformed)
            patched_code = ast.unparse(transformed)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(patched_code)
            print(f"[+] Hot-patch successfully deployed to: {filepath}")
            return True
        except Exception as e:
            print(f"[!] Hot-patch failed: {e}")
            return False


class SecureASTEngine:
    class ThreatTransformer(ast.NodeTransformer):
        def visit_Call(self, node: ast.Call) -> ast.AST:
            if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
                return ast.Constant(value=None)
            if isinstance(node.func, ast.Attribute) and node.func.attr in ["system", "popen"]:
                return ast.Constant(value=0)
            return self.generic_visit(node)

    @classmethod
    def analyze_source(cls, source_code: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            tree = ast.parse(source_code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
                        findings.append({"line": node.lineno, "severity": "CRITICAL", "type": "Dynamic Execution Risk", "desc": f"Forbidden function: {node.func.id}()"})
                    elif isinstance(node.func, ast.Attribute) and node.func.attr in ["popen", "system"]:
                        findings.append({"line": node.lineno, "severity": "HIGH", "type": "Subprocess Injection", "desc": f"Unsafe execution via {node.func.attr}()"})
        except SyntaxError as e:
            findings.append({"line": e.lineno, "severity": "ERROR", "type": "Syntax Error", "desc": str(e)})
        return findings

    @classmethod
    def patch_file(cls, filepath: str) -> bool:
        if not os.path.isfile(filepath):
            return False
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                original_code = f.read()
            tree = ast.parse(original_code)
            transformer = cls.ThreatTransformer()
            patched_tree = transformer.visit(tree)
            ast.fix_missing_locations(patched_tree)
            patched_source = ast.unparse(patched_tree)
            backup_file = f"{filepath}.bak"
            shutil.copyfile(filepath, backup_file)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(patched_source)
            os.remove(backup_file)
            return True
        except Exception as e:
            sys.stderr.write(f"[!] AST Patch Engine Failure: {e}\n")
            return False


class StaticCodeAnalyzer:
    """Performs static code analysis (SAST), vulnerability checks, and automated fixes."""
    
    @staticmethod
    def analyze_python_code(code: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            parsed = ast.parse(code)
            for node in ast.walk(parsed):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
                        findings.append({
                            "line": node.lineno,
                            "type": "Dangerous Function",
                            "severity": "HIGH",
                            "message": f"Use of unsafe call: {node.func.id}()"
                        })
                    elif isinstance(node.func, ast.Attribute) and node.func.attr in ["popen", "system"]:
                        findings.append({
                            "line": node.lineno,
                            "type": "Command Injection Risk",
                            "severity": "HIGH",
                            "message": f"Potential OS command execution via {node.func.attr}()"
                        })
        except SyntaxError as e:
            findings.append({"line": e.lineno, "type": "Syntax Error", "severity": "ERROR", "message": str(e)})

        secret_patterns = [
            (r'(?i)(api[_\-]?key|secret[_\-]?key|password)\s*=\s*[\'"][^\'"]+[\'"]', "Hardcoded Secret Risk")
        ]
        for line_idx, line in enumerate(code.splitlines(), start=1):
            for pattern, issue in secret_patterns:
                if re.search(pattern, line):
                    findings.append({
                        "line": line_idx,
                        "type": issue,
                        "severity": "MEDIUM",
                        "message": f"Line contains suspected hardcoded credential or key."
                    })

        return findings

    @staticmethod
    def propose_secure_fix(finding: Dict[str, Any], code_line: str) -> str:
        if finding["type"] == "Command Injection Risk":
            return "# FIX: Replace os.system/popen with subprocess.run(..., shell=False)"
        elif finding["type"] == "Dangerous Function":
            return "# FIX: Replace eval/exec with ast.literal_eval or structured parsing"
        elif finding["type"] == "Hardcoded Secret Risk":
            return "# FIX: Load sensitive value from os.environ.get('SECRET_KEY')"
        return code_line

class SystemMonitor:
    """Handles log analysis, network inspection, and file integrity monitoring."""

    @staticmethod
    def inspect_active_connections() -> List[Dict[str, str]]:
        res = execute_system_command("netstat -ano", environment="cmd")
        connections = []
        if res.get("returncode") == 0:
            lines = res["stdout"].splitlines()
            for line in lines:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 4 and parts[0] in ["TCP", "UDP"]:
                    connections.append({
                        "proto": parts[0],
                        "local_addr": parts[1],
                        "foreign_addr": parts[2],
                        "state": parts[3] if parts[0] == "TCP" and len(parts) > 4 else "N/A",
                        "pid": parts[-1]
                    })
        return connections

    @staticmethod
    def calculate_file_hash(filepath: str) -> Optional[str]:
        if not os.path.exists(filepath):
            return None
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def check_integrity_drift(baseline: Dict[str, str], target_dir: str) -> Dict[str, Any]:
        current_hashes = {}
        drift = {"modified": [], "added": [], "deleted": []}
        
        for root, _, files in os.walk(target_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, target_dir)
                file_hash = SystemMonitor.calculate_file_hash(full_path)
                if file_hash:
                    current_hashes[rel_path] = file_hash

        for rel_path, orig_hash in baseline.items():
            if rel_path not in current_hashes:
                drift["deleted"].append(rel_path)
            elif current_hashes[rel_path] != orig_hash:
                drift["modified"].append(rel_path)

        for rel_path in current_hashes:
            if rel_path not in baseline:
                drift["added"].append(rel_path)

        return drift


# =============================================================================
# Honeypot SSH Server
# =============================================================================

class HoneypotManager:
    """Manages AI-powered SSH honeypot for attacker interaction logging."""
    def __init__(self):
        self.running = False
        self.connections = []
        self.logs = []
        self._thread = None

    def start(self, host="0.0.0.0", port=2222):
        self.running = True
        self._thread = threading.Thread(target=self._run, args=(host, port), daemon=True)
        self._thread.start()
        return {"status": "started", "host": host, "port": port}

    def stop(self):
        self.running = False
        return {"status": "stopped"}

    def status(self):
        return {
            "running": self.running,
            "connections": self.connections[-10:],
            "logs": self.logs[-20:]
        }

    def _run(self, host, port):
        try:
            import socket
            import paramiko
            import requests
            
            OLLAMA_URL = "http://localhost:11434/api/generate"
            OLLAMA_MODEL = "llama3:8b"
            SYSTEM_PROMPT = """You are a vulnerable Ubuntu 22.04 LTS terminal shell.
            Return ONLY raw terminal output. No explanations or markdown."""

            def generate_llm_response(command, history):
                payload = {
                    "model": OLLAMA_MODEL,
                    "prompt": f"{SYSTEM_PROMPT}\nSession: {history}\nCommand: {command}",
                    "stream": False,
                    "options": {"temperature": 0.2, "num_predict": 200}
                }
                try:
                    r = requests.post(OLLAMA_URL, json=payload, timeout=5)
                    if r.status_code == 200:
                        return r.json().get("response", "command not found")
                except Exception:
                    pass
                return "command not found"

            class HoneypotServer(paramiko.ServerInterface):
                def check_channel_request(self, kind, chanid):
                    return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

                def check_auth_password(self, username, password):
                    self.logs.append({"event": "login", "username": username, "password": password})
                    return paramiko.AUTH_SUCCESSFUL

                def check_channel_shell_request(self, channel):
                    return True

                def check_channel_pty_request(self, channel, term, modes, height, width, pixelwidth, pixelheight):
                    return True

            host_key = paramiko.RSAKey.generate(2048)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(100)

            while self.running:
                try:
                    sock.settimeout(1.0)
                    client, addr = sock.accept()
                    self.connections.append({"remote": f"{addr[0]}:{addr[1]}", "time": time.strftime("%Y-%m-%dT%H:%M:%SZ")})
                    
                    transport = paramiko.Transport(client)
                    transport.add_server_key(host_key)
                    server = HoneypotServer()
                    server.logs = self.logs
                    
                    try:
                        transport.start_server(server=server)
                    except paramiko.SSHException:
                        client.close()
                        continue

                    channel = transport.accept(20)
                    if channel is None:
                        client.close()
                        continue

                    channel.send(b"Welcome to Ubuntu 22.04 LTS\r\n\r\n")
                    prompt = b"ubuntu@server:~$ "
                    channel.send(prompt)
                    
                    history = ""
                    buf = ""
                    
                    while self.running:
                        try:
                            data = channel.recv(1024).decode("utf-8", errors="ignore")
                            if not data:
                                break
                            
                            if data in ('\r', '\n'):
                                channel.send(b"\r\n")
                                cmd = buf.strip()
                                buf = ""
                                
                                if cmd.lower() in ("exit", "logout"):
                                    channel.send(b"logout\r\n")
                                    break
                                
                                if cmd:
                                    out = generate_llm_response(cmd, history)
                                    history += f"\n$ {cmd}\n{out}"
                                    channel.send(out.replace("\n", "\r\n").encode() + b"\r\n")
                                
                                channel.send(prompt)
                            
                            elif data in ('\x08', '\x7f'):
                                if buf:
                                    buf = buf[:-1]
                                    channel.send(b"\b \b")
                            
                            else:
                                buf += data
                                channel.send(data.encode())
                        
                        except Exception:
                            break
                    
                    channel.close()
                    transport.close()
                    client.close()
                
                except socket.timeout:
                    continue
                except Exception:
                    time.sleep(1)
            
            sock.close()
        except Exception as e:
            print(f"[!] Honeypot error: {e}")


# =============================================================================
# Quantum Readiness Checker
# =============================================================================

class QuantumReadinessChecker:
    """Audits cryptographic configurations for post-quantum readiness."""
    @staticmethod
    def audit_crypto_readiness(target_path: str = None) -> Dict[str, Any]:
        findings = []
        recommendations = []
        
        if target_path and os.path.exists(target_path):
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            if "RSA" in content and "2048" in content:
                findings.append({"item": "RSA 2048-bit", "status": "VULNERABLE", "reason": "Shor's algorithm breaks RSA"})
                recommendations.append("Migrate to RSA-4096 or post-quantum key encapsulation mechanisms (KEMs)")
            
            if "ECDSA" in content or "elliptic" in content.lower():
                findings.append({"item": "ECDSA/ECC", "status": "VULNERABLE", "reason": "Shor's algorithm breaks ECC"})
                recommendations.append("Plan migration to CRYSTALS-Dilithium or Falcon")
            
            if "AES-256" in content:
                findings.append({"item": "AES-256", "status": "ACCEPTABLE", "reason": "Grover's algorithm reduces security to ~128-bit; still acceptable with 256-bit keys"})
            
            if "SHA-1" in content or "sha1" in content.lower():
                findings.append({"item": "SHA-1", "status": "CRITICAL", "reason": "Already broken; quantum accelerates collision attacks"})
                recommendations.append("Immediately replace SHA-1 with SHA-256 or SHA-3")
            
            if "SHA-256" in content or "sha256" in content.lower():
                findings.append({"item": "SHA-256", "status": "ACCEPTABLE", "reason": "Grover's reduces to ~128-bit; acceptable for now"})
                recommendations.append("Monitor NIST PQC standards; plan migration to SHA-3/Keccak")
        
        return {
            "target": target_path or "system",
            "findings": findings,
            "recommendations": recommendations,
            "post_quantum_ready": all(f.get("status") != "VULNERABLE" for f in findings) if findings else True
        }


# =============================================================================
# Benchmark / Evaluation Runner
# =============================================================================

class BenchmarkRunner:
    """Closed-loop autonomous defense benchmark runner."""
    @staticmethod
    def run_benchmark(tools: List[str] = None, iterations: int = 1) -> Dict[str, Any]:
        if tools is None:
            tools = ["static_analysis", "secret_scan", "network_inspect"]
        
        from cyber_agent import CyberAgent
        agent = CyberAgent(workspace_path=".")
        
        results = []
        for i in range(iterations):
            iteration = {"iteration": i + 1, "tools": {}}
            for tool in tools:
                start = time.time()
                try:
                    args = {}
                    if tool == "static_analysis":
                        args = {"code": "import os\nprint('test')"}
                    elif tool == "secret_scan":
                        args = {"content": "API_KEY = 'test'"}
                    elif tool == "entropy_check":
                        args = {"filepath": "key_manager.py"}
                    elif tool == "url_similarity_check":
                        args = {"domain": "test.com", "known_domains": ["example.com"]}
                    elif tool == "ai_triage_correlate":
                        args = {"scan_results": [{"tool": "static_analysis", "findings": []}]}
                    elif tool == "ai_anomaly_baseline":
                        args = {"current_connections": [], "baseline_ports": [80, 443]}
                    
                    res = agent.execute_tool(tool, args)
                    iteration["tools"][tool] = {
                        "success": res.get("success", False),
                        "latency_ms": round((time.time() - start) * 1000, 2),
                        "error": res.get("error", "")
                    }
                except Exception as e:
                    iteration["tools"][tool] = {
                        "success": False,
                        "latency_ms": round((time.time() - start) * 1000, 2),
                        "error": str(e)
                    }
            results.append(iteration)
        
        return {
            "benchmark": "autonomous_defense_loop",
            "iterations": iterations,
            "tools_tested": tools,
            "results": results,
            "summary": {
                "total_runs": sum(1 for r in results for _ in r["tools"]),
                "successful_runs": sum(1 for r in results for t in r["tools"].values() if t["success"]),
                "avg_latency_ms": round(sum(t["latency_ms"] for r in results for t in r["tools"].values()) / max(1, sum(1 for r in results for _ in r["tools"])), 2)
            }
        }


# =============================================================================
# Functional OSINT, Web Recon, Email Security, TLS, Cloud Security, Secret Scanning
# Integrated from ideas/shaan ideas-1.py with bug fixes
# =============================================================================

import socket
import ssl
import dns.resolver
import dns.reversename
import ipaddress
from typing import List, Dict, Any, Optional

class OSINTRecon:
    """Functional OSINT using DNS, RDAP, and public data sources."""
    
    @staticmethod
    def enumerate_subdomains(domain: str, wordlist: Optional[List[str]] = None) -> Dict[str, Any]:
        """Resolve common subdomains via DNS."""
        if wordlist is None:
            wordlist = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "portal", "vpn", "cloud", "git", "jira", "wiki", "blog", "shop", "support", "cdn", "static", "app"]
        found = []
        for sub in wordlist:
            fqdn = f"{sub}.{domain}"
            try:
                answers = dns.resolver.resolve(fqdn, 'A', lifetime=3)
                ips = [str(r) for r in answers]
                found.append({"subdomain": fqdn, "ip": ips[0], "all_ips": ips})
            except Exception:
                pass
        return {"domain": domain, "subdomains_found": len(found), "subdomains": found}
    
    @staticmethod
    def reverse_dns_lookup(ip_address: str) -> Dict[str, Any]:
        """Perform reverse DNS lookup."""
        try:
            rev = dns.reversename.from_address(ip_address)
            answers = dns.resolver.resolve(rev, 'PTR', lifetime=5)
            hostnames = [str(r).rstrip('.') for r in answers]
            return {"ip": ip_address, "hostnames": hostnames}
        except Exception as e:
            return {"ip": ip_address, "hostnames": [], "error": str(e)}
    
    @staticmethod
    def dns_record_enumeration(domain: str, record_type: str = "A") -> Dict[str, Any]:
        """Enumerate DNS records."""
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=5)
            records = [str(r) for r in answers]
            return {"domain": domain, "type": record_type, "records": records}
        except Exception as e:
            return {"domain": domain, "type": record_type, "records": [], "error": str(e)}
    
    @staticmethod
    def check_cloudflare(domain: str) -> Dict[str, Any]:
        """Check if domain is behind Cloudflare via DNS."""
        try:
            answers = dns.resolver.resolve(domain, 'A', lifetime=5)
            cf_ips = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"]
            for r in answers:
                ip = str(r)
                for cidr in cf_ips:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                        return {"domain": domain, "behind_cloudflare": True, "ip": ip}
            return {"domain": domain, "behind_cloudflare": False}
        except Exception as e:
            return {"domain": domain, "behind_cloudflare": None, "error": str(e)}


class WebRecon:
    """Functional web reconnaissance using HTTP requests."""
    
    @staticmethod
    def http_headers(url: str, timeout: int = 10) -> Dict[str, Any]:
        """Fetch and analyze HTTP security headers."""
        try:
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            headers = dict(resp.headers)
            security_headers = {
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "MISSING"),
                "Content-Security-Policy": headers.get("Content-Security-Policy", "MISSING"),
                "X-Frame-Options": headers.get("X-Frame-Options", "MISSING"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "MISSING"),
                "Referrer-Policy": headers.get("Referrer-Policy", "MISSING"),
                "Permissions-Policy": headers.get("Permissions-Policy", "MISSING"),
            }
            missing = [k for k, v in security_headers.items() if v == "MISSING"]
            server = headers.get("Server", "unknown")
            return {
                "url": url,
                "status_code": resp.status_code,
                "final_url": resp.url,
                "server": server,
                "security_headers": security_headers,
                "missing_security_headers": missing,
                "score": max(0, 5 - len(missing))
            }
        except Exception as e:
            return {"url": url, "error": str(e)}
    
    @staticmethod
    def robots_txt(url: str, timeout: int = 10) -> Dict[str, Any]:
        """Fetch and parse robots.txt."""
        try:
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            resp = requests.get(robots_url, timeout=timeout)
            if resp.status_code == 200:
                disallow = re.findall(r"Disallow:\s*(.+)", resp.text, re.IGNORECASE)
                allow = re.findall(r"Allow:\s*(.+)", resp.text, re.IGNORECASE)
                sitemaps = re.findall(r"Sitemap:\s*(.+)", resp.text, re.IGNORECASE)
                return {
                    "url": robots_url,
                    "found": True,
                    "disallow_paths": [d.strip() for d in disallow],
                    "allow_paths": [a.strip() for a in allow],
                    "sitemaps": [s.strip() for s in sitemaps]
                }
            return {"url": robots_url, "found": False, "status": resp.status_code}
        except Exception as e:
            return {"url": url, "error": str(e)}
    
    @staticmethod
    def tech_fingerprint(url: str, timeout: int = 10) -> Dict[str, Any]:
        """Basic technology fingerprinting from HTTP headers and content."""
        try:
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            tech = []
            if "x-powered-by" in headers:
                tech.append({"name": headers["x-powered-by"], "category": "backend"})
            if "server" in headers:
                tech.append({"name": headers["server"], "category": "server"})
            if "x-aspnet-version" in headers:
                tech.append({"name": f"ASP.NET {headers['x-aspnet-version']}", "category": "framework"})
            if "x-aspnetmvc-version" in headers:
                tech.append({"name": f"ASP.NET MVC {headers['x-aspnetmvc-version']}", "category": "framework"})
            if "x-drupal-cache" in headers or "drupal" in resp.text.lower()[:1000]:
                tech.append({"name": "Drupal", "category": "cms"})
            if "x-generator" in headers and "wordpress" in headers["x-generator"].lower():
                tech.append({"name": "WordPress", "category": "cms"})
            if "react" in resp.text.lower()[:5000] or "next.js" in resp.text.lower()[:5000]:
                tech.append({"name": "React/Next.js", "category": "frontend"})
            if "wp-content" in resp.text:
                tech.append({"name": "WordPress", "category": "cms"})
            if "joomla" in resp.text.lower():
                tech.append({"name": "Joomla", "category": "cms"})
            return {"url": url, "technologies": tech, "detected": len(tech) > 0}
        except Exception as e:
            return {"url": url, "error": str(e)}
    
    @staticmethod
    def directory_listing_check(url: str, paths: Optional[List[str]] = None, timeout: int = 5) -> Dict[str, Any]:
        """Check for common sensitive paths."""
        if paths is None:
            paths = ["/admin", "/login", "/wp-admin", "/.git", "/.env", "/backup", "/config", "/robots.txt", "/sitemap.xml", "/api", "/graphql", "/swagger", "/actuator"]
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        found = []
        for path in paths:
            try:
                resp = requests.get(f"{url}{path}", timeout=timeout, allow_redirects=False, verify=False)
                if resp.status_code in [200, 301, 302, 403]:
                    found.append({"path": path, "status": resp.status_code, "accessible": resp.status_code == 200})
            except Exception:
                pass
        return {"url": url, "sensitive_paths": found, "count": len(found)}


class EmailSecurityAnalyzer:
    """Functional email security checks via DNS lookups."""
    
    @staticmethod
    def check_spf(domain: str) -> Dict[str, Any]:
        """Check SPF record."""
        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
            spf_records = [str(r).strip('"') for r in answers if "v=spf1" in str(r).lower()]
            if not spf_records:
                return {"domain": domain, "spf_found": False, "records": [], "status": "MISSING"}
            record = spf_records[0]
            includes = re.findall(r"include:([^\s]+)", record)
            ip4 = re.findall(r"ip4:([^\s]+)", record)
            mx = "mx" in record.lower()
            all_mechanism = re.search(r"\s(all|~all|-all|\?all)\s", record)
            all_policy = all_mechanism.group(1) if all_mechanism else "unknown"
            return {
                "domain": domain,
                "spf_found": True,
                "record": record,
                "includes": includes,
                "ip4_ranges": ip4,
                "uses_mx": mx,
                "all_policy": all_policy,
                "status": "SOFTFAIL" if all_policy == "~all" else "HARDFAIL" if all_policy == "-all" else "NEUTRAL" if all_policy == "?all" else "PASS"
            }
        except Exception as e:
            return {"domain": domain, "spf_found": False, "error": str(e)}
    
    @staticmethod
    def check_dmarc(domain: str) -> Dict[str, Any]:
        """Check DMARC record."""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=5)
            dmarc_records = [str(r).strip('"') for r in answers if "v=dmarc1" in str(r).lower()]
            if not dmarc_records:
                return {"domain": domain, "dmarc_found": False, "record": None, "status": "MISSING"}
            record = dmarc_records[0]
            policy = re.search(r"p=(none|quarantine|reject)", record, re.IGNORECASE)
            rua = re.findall(r"rua=mailto:([^\s;]+)", record)
            ruf = re.findall(r"ruf=mailto:([^\s;]+)", record)
            pct = re.search(r"pct=(\d+)", record, re.IGNORECASE)
            return {
                "domain": domain,
                "dmarc_found": True,
                "record": record,
                "policy": policy.group(1).lower() if policy else "none",
                "rua": rua,
                "ruf": ruf,
                "percentage": int(pct.group(1)) if pct else 100,
                "status": "REJECT" if policy and policy.group(1).lower() == "reject" else "QUARANTINE" if policy and policy.group(1).lower() == "quarantine" else "NONE"
            }
        except Exception as e:
            return {"domain": domain, "dmarc_found": False, "error": str(e)}
    
    @staticmethod
    def check_dkim(domain: str, selector: str = "default") -> Dict[str, Any]:
        """Check DKIM record for a selector."""
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, 'TXT', lifetime=5)
            dkim_records = [str(r).strip('"') for r in answers if "v=dkim1" in str(r).lower()]
            if not dkim_records:
                return {"domain": domain, "selector": selector, "dkim_found": False, "record": None}
            return {
                "domain": domain,
                "selector": selector,
                "dkim_found": True,
                "record": dkim_records[0],
                "status": "VALID"
            }
        except Exception as e:
            return {"domain": domain, "selector": selector, "dkim_found": False, "error": str(e)}
    
    @staticmethod
    def email_security_posture(domain: str) -> Dict[str, Any]:
        """Complete email security posture check."""
        spf = EmailSecurityAnalyzer.check_spf(domain)
        dmarc = EmailSecurityAnalyzer.check_dmarc(domain)
        dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "s1"]
        dkim_results = []
        for sel in dkim_selectors:
            dkim = EmailSecurityAnalyzer.check_dkim(domain, sel)
            if dkim.get("dkim_found"):
                dkim_results.append(dkim)
        score = 0
        if spf.get("spf_found"):
            score += 1
        if dmarc.get("dmarc_found") and dmarc.get("policy") in ["quarantine", "reject"]:
            score += 1
        if dkim_results:
            score += 1
        verdict = "GOOD" if score == 3 else "FAIR" if score == 2 else "POOR" if score == 1 else "MISSING"
        return {
            "domain": domain,
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim_results,
            "score": score,
            "max_score": 3,
            "verdict": verdict,
            "recommendations": [
                "Add SPF record" if not spf.get("spf_found") else None,
                "Set DMARC policy to quarantine or reject" if not dmarc.get("dmarc_found") or dmarc.get("policy") == "none" else None,
                "Publish DKIM records" if not dkim_results else None
            ]
        }


class TLSAnalyzer:
    """Functional TLS certificate and configuration analysis."""
    
    @staticmethod
    def inspect_certificate(host: str, port: int = 443, timeout: int = 10) -> Dict[str, Any]:
        """Inspect TLS certificate using Python ssl module."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            san = cert.get("subjectAltName", ())
            sans = [entry[1] for entry in san if entry[0] == "DNS"]
            serial = cert.get("serialNumber", "")
            sig_alg = cert.get("signatureAlgorithm", "")
            return {
                "host": host,
                "port": port,
                "version": version,
                "cipher": cipher[0] if cipher else "unknown",
                "cipher_bits": cipher[2] if cipher else 0,
                "subject": subject,
                "issuer": issuer,
                "san": sans,
                "not_before": not_before,
                "not_after": not_after,
                "serial": serial,
                "signature_algorithm": sig_alg,
                "expired": False
            }
        except ssl.SSLCertVerificationError as e:
            return {"host": host, "port": port, "error": f"Certificate verification failed: {e}", "expired": None}
        except Exception as e:
            return {"host": host, "port": port, "error": str(e), "expired": None}
    
    @staticmethod
    def check_tls_configuration(host: str, port: int = 443) -> Dict[str, Any]:
        """Check TLS configuration for common weaknesses."""
        cert_info = TLSAnalyzer.inspect_certificate(host, port)
        if "error" in cert_info:
            return cert_info
        issues = []
        if cert_info.get("cipher_bits", 0) < 128:
            issues.append("Weak cipher key length")
        if "TLSv1.0" in cert_info.get("version", "") or "TLSv1.1" in cert_info.get("version", ""):
            issues.append("Outdated TLS version")
        issuer = cert_info.get("issuer", {}).get("organizationName", "").lower()
        if "let's encrypt" in issuer:
            issues.append("ACME certificate (short-lived, acceptable)")
        return {
            "host": host,
            "port": port,
            "tls_version": cert_info.get("version"),
            "cipher": cert_info.get("cipher"),
            "issues": issues,
            "secure": len([i for i in issues if "short-lived" not in i.lower()]) == 0
        }
    
    @staticmethod
    def check_certificate_transparency(host: str) -> Dict[str, Any]:
        """Check certificate transparency logs via crt.sh."""
        try:
            url = f"https://crt.sh/?q=%25.{host}&output=json"
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    domains = set()
                    for entry in data:
                        name = entry.get("common_name", "")
                        domains.add(name)
                        for san in entry.get("name_value", "").split("\n"):
                            if san.strip():
                                domains.add(san.strip())
                    return {"host": host, "ct_logs_found": True, "unique_domains": len(domains), "sample_domains": list(domains)[:10]}
            return {"host": host, "ct_logs_found": False, "status": resp.status_code}
        except Exception as e:
            return {"host": host, "ct_logs_found": None, "error": str(e)}


class CloudSecurityChecker:
    """Functional cloud security checks for exposed resources."""
    
    @staticmethod
    def check_s3_bucket(bucket_name: str) -> Dict[str, Any]:
        """Check if an S3 bucket is publicly accessible."""
        bucket_name = bucket_name.replace("https://", "").replace("http://", "").replace("s3.amazonaws.com/", "").replace(".s3.amazonaws.com", "")
        results = {"bucket": bucket_name, "public": False, "findings": []}
        urls_to_check = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
            f"http://{bucket_name}.s3.amazonaws.com"
        ]
        for url in urls_to_check:
            try:
                resp = requests.get(url, timeout=8, allow_redirects=False)
                if resp.status_code == 200:
                    results["public"] = True
                    results["findings"].append({"url": url, "accessible": True, "status": resp.status_code})
                    break
                elif resp.status_code in [301, 302, 403]:
                    results["findings"].append({"url": url, "status": resp.status_code, "note": "Redirect/Forbidden"})
            except requests.exceptions.SSLError:
                results["findings"].append({"url": url, "status": "SSL_ERROR"})
            except Exception as e:
                results["findings"].append({"url": url, "error": str(e)})
        return results
    
    @staticmethod
    def check_azure_blob(container_name: str) -> Dict[str, Any]:
        """Check if Azure blob container is public."""
        container_name = container_name.replace("https://", "").replace("http://", "").replace(".blob.core.windows.net", "")
        url = f"https://{container_name}.blob.core.windows.net"
        try:
            resp = requests.get(url, timeout=8, allow_redirects=False)
            return {
                "container": container_name,
                "url": url,
                "public": resp.status_code == 200,
                "status": resp.status_code
            }
        except Exception as e:
            return {"container": container_name, "url": url, "public": None, "error": str(e)}
    
    @staticmethod
    def check_google_bucket(bucket_name: str) -> Dict[str, Any]:
        """Check if Google Cloud Storage bucket is public."""
        bucket_name = bucket_name.replace("https://", "").replace("http://", "").replace("storage.googleapis.com/", "").replace(".storage.googleapis.com", "")
        url = f"https://storage.googleapis.com/{bucket_name}"
        try:
            resp = requests.get(url, timeout=8, allow_redirects=False)
            return {
                "bucket": bucket_name,
                "url": url,
                "public": resp.status_code == 200,
                "status": resp.status_code
            }
        except Exception as e:
            return {"bucket": bucket_name, "url": url, "public": None, "error": str(e)}
    
    @staticmethod
    def check_exposed_admin_panels(url: str) -> Dict[str, Any]:
        """Check for exposed admin panels and sensitive endpoints."""
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        paths = [
            "/admin", "/admin/login", "/adminpanel", "/administrator", "/wp-admin", "/wp-login.php",
            "/phpmyadmin", "/pma", "/myadmin", "/.env", "/.git/config", "/.svn/entries",
            "/backup", "/backup.sql", "/db.sql", "/dump.sql", "/config.php", "/config.json",
            "/api/v1", "/api/v2", "/graphql", "/swagger", "/swagger-ui", "/actuator", "/actuator/env",
            "/.well-known/security.txt", "/robots.txt", "/sitemap.xml"
        ]
        found = []
        for path in paths:
            try:
                resp = requests.get(f"{url}{path}", timeout=5, allow_redirects=False, verify=False)
                if resp.status_code in [200, 301, 302, 403]:
                    found.append({"path": path, "status": resp.status_code, "accessible": resp.status_code == 200})
            except Exception:
                pass
        return {"url": url, "endpoints": found, "sensitive_count": len(found)}


class ImprovedSecretScanner:
    """Enhanced secret scanning with more patterns."""
    
    PATTERNS = [
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token", "CRITICAL"),
        (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token", "CRITICAL"),
        (r'github_pat_[a-zA-Z0-9_]{22,}', "GitHub Fine-grained PAT", "CRITICAL"),
        (r'xox[baprs]-[0-9a-zA-Z-]+', "Slack Token", "CRITICAL"),
        (r'xoxp-[0-9a-zA-Z-]+', "Slack User Token", "CRITICAL"),
        (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private Key", "CRITICAL"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "CRITICAL"),
        (r'(?i)aws_secret_access_key\s*=\s*["\']?([a-zA-Z0-9/+=]{40})', "AWS Secret Key", "CRITICAL"),
        (r'(?i)api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', "Generic API Key", "HIGH"),
        (r'(?i)secret[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', "Generic Secret Key", "HIGH"),
        (r'(?i)password\s*[:=]\s*["\']?([a-zA-Z0-9!@#$%^&*]{6,})', "Hardcoded Password", "HIGH"),
        (r'-----BEGIN OPENSSH PRIVATE KEY-----', "SSH Private Key", "CRITICAL"),
        (r'sk-[a-zA-Z0-9]{48}', "OpenAI API Key", "CRITICAL"),
        (r'w/r/[a-zA-Z0-9_-]+', "WolframAlpha API Key", "HIGH"),
        (r'[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+@[a-z0-9.-]+\.[a-z]{2,}', "Basic Auth Credentials", "HIGH"),
        (r'(?i)(mongodb|mysql|postgresql|postgres):\/\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@', "Database Connection String", "CRITICAL"),
        (r'-----BEGIN CERTIFICATE-----', "PEM Certificate", "MEDIUM"),
        (r'(?i)client_secret\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{10,})', "OAuth Client Secret", "HIGH"),
    ]
    
    @staticmethod
    def scan_content(content: str) -> List[Dict[str, Any]]:
        """Scan content for secrets."""
        leaks = []
        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            for pattern, secret_type, severity in ImprovedSecretScanner.PATTERNS:
                matches = re.finditer(pattern, line)
                for match in matches:
                    leaks.append({
                        "line": line_num,
                        "type": secret_type,
                        "severity": severity,
                        "match": match.group(0),
                        "context": line.strip()
                    })
        return leaks


# =============================================================================
# Tool Registration
# =============================================================================

def register_all_default_tools(registry: ToolRegistry):
    """Registers the complete tool catalog into the specified ToolRegistry."""
    global _SKIP_SUMMARY_REPORTED
    registry.audit_logger.suppress(True)
    # Reset per-call: this module-level list would otherwise accumulate across
    # every registration in a process, so the skip summary grew 2, 4, 6, ...
    _OPTIONAL_TOOL_GROUPS_SKIPPED.clear()
    # Workspace access. These were previously only registered in the shadowed
    # duplicate of this function, so the agent had no way to list or read files.
    registry.register_tool(ToolDefinition(
        "workspace_list_files", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY,
        python_func=lambda root=".", pattern="*", max_results=200: _list_workspace_files(root, pattern, max_results),
    ))
    registry.register_tool(ToolDefinition(
        "workspace_read_file", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY,
        python_func=lambda filepath="", max_bytes=200000: _read_workspace_file(filepath, max_bytes),
    ))
    registry.register_tool(ToolDefinition(
        "list_available_drives", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY,
        python_func=_list_available_drives,
    ))
    # Python & Diagnostics
    registry.register_tool(ToolDefinition(
        name="static_analysis",
        environments=["cross_platform"],
        command_template="",
        risk_level=RiskLevel.READ_ONLY,
        python_func=StaticCodeAnalyzer.analyze_python_code
    ))
    registry.register_tool(ToolDefinition(
        name="network_inspect",
        environments=["cross_platform"],
        command_template="",
        risk_level=RiskLevel.READ_ONLY,
        python_func=SystemMonitor.inspect_active_connections
    ))

    # Fallback Pairs
    has_native_nmap = shutil.which("nmap") is not None
    if has_native_nmap:
        registry.register_tool(ToolDefinition("nmap_scan", ["native_windows"], "nmap {target}", risk_level=RiskLevel.READ_ONLY))
    else:
        registry.register_tool(ToolDefinition("nmap_scan", ["wsl_linux"], "nmap {target}", risk_level=RiskLevel.READ_ONLY))

    registry.register_tool(ToolDefinition("clamav_scan", ["wsl_linux"], "clamscan -r {target}", risk_level=RiskLevel.READ_ONLY, fallback_tool="windows_defender_scan"))
    defender_path = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")
    registry.register_tool(ToolDefinition("windows_defender_scan", ["native_windows"], f'& "{defender_path}" -Scan -ScanType 3 -File "{{target}}"', risk_level=RiskLevel.READ_ONLY))
    
    registry.register_tool(ToolDefinition("rkhunter_scan", ["wsl_linux"], "rkhunter --check --sk", risk_level=RiskLevel.READ_ONLY, fallback_tool="autoruns_scan"))
    registry.register_tool(ToolDefinition("autoruns_scan", ["native_windows"], "autorunsc64.exe -a * -ct", risk_level=RiskLevel.READ_ONLY))
    
    registry.register_tool(ToolDefinition("aide_check", ["wsl_linux"], "aide --check", risk_level=RiskLevel.READ_ONLY, fallback_tool="powershell_file_hash"))
    registry.register_tool(ToolDefinition("powershell_file_hash", ["native_windows"], "powershell -NoProfile -Command \"Get-ChildItem -Path '{target}' -Recurse | Get-FileHash\"", risk_level=RiskLevel.READ_ONLY))
    
    registry.register_tool(ToolDefinition("auditd_monitor", ["wsl_linux"], "ausearch -m execve", risk_level=RiskLevel.READ_ONLY, fallback_tool="windows_process_monitor"))
    registry.register_tool(ToolDefinition("windows_process_monitor", ["native_windows"], "powershell -NoProfile -Command \"Get-Process | Select-Object Id, ProcessName, Path\"", risk_level=RiskLevel.READ_ONLY))

    # Reconnaissance & Network Analysis
    registry.register_tool(ToolDefinition("tshark_capture", ["wsl_linux", "native_windows"], "tshark -i {interface} -c {count}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("netcat_test", ["wsl_linux", "native_windows"], "nc -zv {host} {port}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("masscan_scan", ["wsl_linux"], "masscan {target} -p{ports}", requires_admin=True, risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("arp_scan", ["wsl_linux"], "arp-scan --localnet", requires_admin=True, risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("netdiscover", ["wsl_linux"], "netdiscover -r {range}", requires_admin=True, risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("traceroute", ["wsl_linux", "native_windows"], "tracert {target}" if sys.platform == "win32" else "traceroute {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("ping", ["cross_platform"], "ping -c 4 {target}" if sys.platform != "win32" else "ping -n 4 {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("nslookup", ["cross_platform"], "nslookup {domain}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("dig", ["wsl_linux"], "dig {domain}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("nikto", ["wsl_linux"], "nikto -h {target}", risk_level=RiskLevel.READ_ONLY))

    # Vulnerability & Malware Scanning
    registry.register_tool(ToolDefinition("yara_scan", ["wsl_linux", "native_windows"], "yara {rules} {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("osv_scanner", ["cross_platform"], "osv-scanner -r {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("grype_scan", ["cross_platform"], "grype {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("trivy_scan", ["cross_platform"], "trivy fs {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("openvas_scan", ["wsl_linux"], "gvm-cli socket --xml '<get_tasks/>'", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("virustotal_scan", ["cross_platform"], "vt file {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("chkrootkit_scan", ["wsl_linux"], "chkrootkit", requires_admin=True, risk_level=RiskLevel.READ_ONLY))

    # Static & Dynamic Code Analysis
    registry.register_tool(ToolDefinition("bandit_scan", ["cross_platform"], "bandit -r {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("semgrep_scan", ["cross_platform"], "semgrep --config p/security-audit {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("codeql_analyze", ["cross_platform"], "codeql database analyze {db} --format=sarif-latest --output={output}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("eslint_security", ["cross_platform"], "npx eslint {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("pylint_check", ["cross_platform"], "pylint {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("flake8_check", ["cross_platform"], "flake8 {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("cppcheck_scan", ["cross_platform"], "cppcheck --enable=all {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("gosec_scan", ["cross_platform"], "gosec ./...", risk_level=RiskLevel.READ_ONLY))

    # File & System Integrity
    registry.register_tool(ToolDefinition("tripwire_check", ["wsl_linux"], "tripwire --check", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("sha256sum", ["cross_platform"], "sha256sum {target}" if sys.platform != "win32" else "powershell -Command \"Get-FileHash '{target}'\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("hashdeep", ["wsl_linux"], "hashdeep -r {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("sysmon_query", ["native_windows"], "powershell -Command \"Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 50\"", risk_level=RiskLevel.READ_ONLY))

    # Forensics & Incident Response
    registry.register_tool(ToolDefinition("volatility_memory", ["cross_platform"], "vol -f {image} {plugin}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("sleuthkit_fls", ["cross_platform"], "fls {image}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("plaso_log2timeline", ["wsl_linux"], "log2timeline.py {output} {image}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("strings_inspect", ["cross_platform"], "strings {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("exiftool_inspect", ["cross_platform"], "exiftool {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("binwalk_inspect", ["wsl_linux"], "binwalk {target}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("capa_detect", ["cross_platform"], "capa {target}", risk_level=RiskLevel.READ_ONLY))

    # Pentesting / Authorized Testing Tools
    registry.register_tool(ToolDefinition("metasploit_console", ["wsl_linux"], "msfconsole -q -x '{command}'", risk_level=RiskLevel.DESTRUCTIVE))
    registry.register_tool(ToolDefinition("zap_cli_scan", ["cross_platform"], "zap-cli quick-scan --self-contained {target}", risk_level=RiskLevel.MODIFIES_SYSTEM))
    registry.register_tool(ToolDefinition("sqlmap_scan", ["cross_platform"], "sqlmap -u '{url}' --batch", risk_level=RiskLevel.MODIFIES_SYSTEM))
    registry.register_tool(ToolDefinition("hydra_test", ["wsl_linux"], "hydra -l {user} -P {passlist} {target} {service}", risk_level=RiskLevel.MODIFIES_SYSTEM))

    # Windows Native Cmdlets & Utilities
    registry.register_tool(ToolDefinition("get_winevent", ["native_windows"], "powershell -Command \"Get-WinEvent -LogName '{log_name}' -MaxEvents 20\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("get_service", ["native_windows"], "powershell -Command \"Get-Service\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("psscriptanalyzer", ["native_windows"], "powershell -Command \"Invoke-ScriptAnalyzer -Path '{target}'\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("wmic_query", ["native_windows"], "wmic {alias} get {properties}", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("netsh_query", ["native_windows"], "netsh interface show interface", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("sc_query", ["native_windows"], "sc query {service}", risk_level=RiskLevel.READ_ONLY))

    # Additional Defensive Tools from ideas
    registry.register_tool(ToolDefinition("secret_scan", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=SecretScanner.scan_text_for_secrets))
    registry.register_tool(ToolDefinition("dependency_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=DependencyAnalyzer.check_python_requirements))
    registry.register_tool(ToolDefinition("terminate_process", ["cross_platform"], "", risk_level=RiskLevel.DESTRUCTIVE, python_func=ProcessManager.terminate_process_by_pid))
    registry.register_tool(ToolDefinition("block_ip", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=FirewallManager.block_ip_address))

    # Process Anomaly Detection (from ideas)
    registry.register_tool(ToolDefinition("detect_cpu_spikes", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ProcessManager.identify_high_cpu_processes))
    registry.register_tool(ToolDefinition("detect_memory_hogs", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ProcessManager.detect_unusual_memory_hogs))
    registry.register_tool(ToolDefinition("audit_background_services", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ProcessManager.audit_hidden_background_services))

    # KeyManager AI Integrated Tools
    registry.register_tool(ToolDefinition("ai_secure_fix", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AiSecurityAssistant.generate_ai_fix))
    registry.register_tool(ToolDefinition("ai_incident_summary", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AiSecurityAssistant.generate_incident_summary))
    registry.register_tool(ToolDefinition("ai_yara_generator", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AiSecurityAssistant.generate_yara_rule))
    registry.register_tool(ToolDefinition("ai_triage_correlate", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AITriageEngine.correlate_findings))
    registry.register_tool(ToolDefinition("ai_explain_risk", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AICodeRiskExplainer.explain_code_risk))
    registry.register_tool(ToolDefinition("ai_anomaly_baseline", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=AIAnomalyBaseline.check_baseline_anomaly))

    # Threat Intelligence / Reputation
    # The VirusTotal and OTX tools are the only ones in this registry that transmit
    # artifact values to a third party, so each description states that outright. The
    # remaining three have no implementation and say so, to save the agent a wasted call.
    for _ti_name, _ti_func, _ti_description in (
        ("virustotal_hash_lookup", ThreatIntel.vt_hash_lookup,
         "Look up a file hash (md5/sha1/sha256) on VirusTotal. Sends the hash to VirusTotal "
         "- third-party disclosure. Returns verdict=unknown if VIRUSTOTAL_API_KEY is unset."),
        ("virustotal_ip_lookup", ThreatIntel.vt_ip_lookup,
         "Look up an IP address on VirusTotal. Sends the IP to VirusTotal - third-party "
         "disclosure. Returns verdict=unknown if VIRUSTOTAL_API_KEY is unset."),
        ("otx_ip_lookup", ThreatIntel.otx_ip_lookup,
         "Look up an IP address on AlienVault OTX and report how many threat pulses list it. "
         "Sends the IP to OTX - third-party disclosure. Returns verdict=unknown if OTX_API_KEY is unset."),
        ("enrich_artifact", ThreatIntel.enrich_artifact,
         "Enrich one artifact across every configured provider at once. Takes artifact_type "
         "('ip' or 'hash') and value, and returns the most severe verdict any provider gave. "
         "Sends the artifact to VirusTotal and/or OTX - third-party disclosure."),
        ("urlscan_check", ThreatIntel.urlscan_lookup,
         "NOT IMPLEMENTED - always returns verdict=unknown without scanning anything."),
        ("abuseipdb_check", ThreatIntel.check_ip_reputation,
         "NOT IMPLEMENTED - always returns verdict=unknown. Use virustotal_ip_lookup or "
         "otx_ip_lookup for real IP reputation."),
        ("shodan_lookup", ThreatIntel.shodan_host_lookup,
         "NOT IMPLEMENTED - always returns verdict=unknown without querying Shodan."),
    ):
        _ti_definition = ToolDefinition(
            _ti_name, ["cross_platform"], "",
            risk_level=RiskLevel.READ_ONLY, python_func=_ti_func,
        )
        _ti_definition.description = _ti_description
        registry.register_tool(_ti_definition)

    # Behavioral Detection
    registry.register_tool(ToolDefinition("sigma_rule_match", ["native_windows"], "", risk_level=RiskLevel.READ_ONLY, python_func=BehaviorDetector.match_sigma_rules))
    registry.register_tool(ToolDefinition("process_tree_analysis", ["native_windows"], "powershell -Command \"Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("suspicious_parent_child", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=BehaviorDetector.flag_suspicious_process_chains))

    # PE / Binary Analysis
    registry.register_tool(ToolDefinition("pe_header_analysis", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=BinaryAnalyzer.analyze_pe_headers))
    registry.register_tool(ToolDefinition("entropy_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=BinaryAnalyzer.calculate_entropy))
    registry.register_tool(ToolDefinition("import_table_scan", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=BinaryAnalyzer.flag_suspicious_imports))

    # Network Deep Inspection
    registry.register_tool(ToolDefinition("dns_exfil_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=NetworkAnalyzer.detect_dns_tunneling))
    registry.register_tool(ToolDefinition("beaconing_detect", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=NetworkAnalyzer.detect_periodic_callbacks))
    registry.register_tool(ToolDefinition("tls_cert_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=NetworkAnalyzer.inspect_tls_certificate))

    # Phishing & Social Engineering Detection
    registry.register_tool(ToolDefinition("email_header_analysis", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=PhishDetector.analyze_email_headers))
    registry.register_tool(ToolDefinition("url_similarity_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=PhishDetector.detect_typosquat))
    registry.register_tool(ToolDefinition("attachment_macro_scan", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=PhishDetector.scan_office_macros))

    # Compliance & Config Auditing
    registry.register_tool(ToolDefinition("cis_benchmark_check", ["native_windows"], "", risk_level=RiskLevel.READ_ONLY, python_func=ComplianceAuditor.run_cis_checks))
    registry.register_tool(ToolDefinition("firewall_rule_audit", ["native_windows"], "powershell -Command \"Get-NetFirewallRule | Where Enabled -eq True\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("open_port_audit", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ComplianceAuditor.audit_listening_ports))
    registry.register_tool(ToolDefinition("password_policy_check", ["native_windows"], "powershell -Command \"net accounts\"", risk_level=RiskLevel.READ_ONLY))

    # Remediation (Gated under MODIFIES_SYSTEM / DESTRUCTIVE)
    registry.register_tool(ToolDefinition("quarantine_file", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=RemediationManager.quarantine_file))
    registry.register_tool(ToolDefinition("disable_startup_entry", ["native_windows"], "", risk_level=RiskLevel.DESTRUCTIVE, python_func=RemediationManager.disable_autorun_entry))
    registry.register_tool(ToolDefinition("revert_registry_key", ["native_windows"], "", risk_level=RiskLevel.DESTRUCTIVE, python_func=RemediationManager.rollback_registry_key))
    registry.register_tool(ToolDefinition("kill_and_block", ["cross_platform"], "", risk_level=RiskLevel.DESTRUCTIVE, python_func=RemediationManager.terminate_and_isolate))

    # Report Generation
    registry.register_tool(ToolDefinition("generate_incident_report", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ReportGenerator.build_incident_summary))

    # IAM & Cloud Security (from ideas)
    registry.register_tool(ToolDefinition("active_directory_privilege_audit", ["native_windows"], "powershell -Command \"Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled\"", risk_level=RiskLevel.READ_ONLY))
    registry.register_tool(ToolDefinition("ssh_key_auditor", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda: {"status": "simulated", "ssh_keys_scanned": 0}))
    registry.register_tool(ToolDefinition("s3_bucket_leak_checker", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda: {"status": "simulated", "buckets_checked": 0}))
    registry.register_tool(ToolDefinition("container_security_audit", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda: {"status": "simulated", "containers_scanned": 0}))

    # Honeypot SSH Server
    registry.register_tool(ToolDefinition("start_honeypot", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: {"status": "simulated", "honeypot": "started"}))
    registry.register_tool(ToolDefinition("stop_honeypot", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: {"status": "simulated", "honeypot": "stopped"}))
    registry.register_tool(ToolDefinition("honeypot_status", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: {"running": False, "connections": [], "logs": []}))

    # Quantum-ready crypto audit
    registry.register_tool(ToolDefinition("quantum_ready_audit", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=QuantumReadinessChecker.audit_crypto_readiness))

    # Benchmark / Evaluation
    registry.register_tool(ToolDefinition("benchmark_run", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=BenchmarkRunner.run_benchmark))

    # Vigil SOC-inspired tools (from cyber_soc_engine)
    try:
        from vigil_tools.sample_data_generator import generate_sample_data, save_to_files
        registry.register_tool(ToolDefinition("soc_generate_sample_data", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: {"status": "generated", "data": generate_sample_data(10, 2)}))
        registry.register_tool(ToolDefinition("soc_save_sample_data", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: {"status": "saved", "files": save_to_files(*generate_sample_data(10, 2))}))
    except Exception as exc:
        _skip_optional_tool_group('soc_generate_sample_data... (vigil_tools.sample_data_generator)', exc)

    try:
        from vigil_tools.finding_enricher import auto_enrich_findings
        registry.register_tool(ToolDefinition("soc_enrich_findings", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: {"enriched": auto_enrich_findings(kw.get("findings", []))}))
    except Exception as exc:
        _skip_optional_tool_group('soc_enrich_findings (vigil_tools.finding_enricher)', exc)

    try:
        from vigil_tools.workflow_compiler import compile_workflow, validate_workflow
        def compile_soc_workflow(markdown: str = "", workflow_name: str = ""):
            if not markdown.strip() and not workflow_name:
                workflow_name = "incident-response"
            if not markdown.strip() and workflow_name:
                from cyber_agent import BUILTIN_WORKFLOWS
                workflow = BUILTIN_WORKFLOWS.get(workflow_name)
                if workflow:
                    markdown = "---\n" f"name: {workflow.name}\n" f"description: {workflow.description}\n" "---\n"
                    markdown += "\n".join(
                        f'- id: {phase.id} name: "{phase.name}" agent: {phase.agent} tools: [{", ".join(phase.tools)}]'
                        for phase in workflow.phases
                    )
                else:
                    return {"error": f"Unknown workflow: {workflow_name}", "phases": [], "raw": ""}
            return compile_workflow(markdown)

        registry.register_tool(ToolDefinition("soc_compile_workflow", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=compile_soc_workflow))
        def validate_soc_workflow(markdown: str = "", workflow_name: str = ""):
            if not markdown.strip():
                compiled = compile_soc_workflow(workflow_name=workflow_name or "incident-response")
                if compiled.get("error"):
                    return {"valid": False, "errors": [compiled["error"]], "workflow": workflow_name}
                markdown = compiled.get("raw", "")
            errors = validate_workflow(markdown)
            return {"valid": not errors, "errors": errors, "workflow": workflow_name or "incident-response"}

        registry.register_tool(ToolDefinition("soc_validate_workflow", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=validate_soc_workflow))
    except Exception as exc:
        _skip_optional_tool_group('soc_compile_workflow... (vigil_tools.workflow_compiler)', exc)

    # CyberDB integration — AI-accessible database layer
    try:
        from cyber_db import get_db
        _db = get_db()

        registry.register_tool(ToolDefinition("db_add_finding", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=lambda **kw: _db.add_finding(kw)))
        registry.register_tool(ToolDefinition("db_get_finding", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: _db.get_finding(kw.get("finding_id", ""))))
        registry.register_tool(ToolDefinition("db_list_findings", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: _db.list_findings(kw)))
        registry.register_tool(ToolDefinition("db_update_finding", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=lambda **kw: _db.update_finding(kw.pop("finding_id", ""), **kw)))
        registry.register_tool(ToolDefinition("db_delete_finding", ["cross_platform"], "", risk_level=RiskLevel.DESTRUCTIVE, python_func=lambda **kw: _db.delete_finding(kw.get("finding_id", ""))))

        registry.register_tool(ToolDefinition("db_create_case", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=lambda **kw: _db.create_case(kw)))
        registry.register_tool(ToolDefinition("db_get_case", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: _db.get_case(kw.get("case_id", ""))))
        registry.register_tool(ToolDefinition("db_list_cases", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: _db.list_cases(kw)))
        registry.register_tool(ToolDefinition("db_update_case", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=lambda **kw: _db.update_case(kw.pop("case_id", ""), **kw)))
        registry.register_tool(ToolDefinition("db_add_case_event", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=lambda **kw: _db.add_case_event(kw.pop("case_id", ""), kw.pop("event", ""))))

        registry.register_tool(ToolDefinition("db_map_mitre", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: _db.map_finding_to_mitre(kw)))
        registry.register_tool(ToolDefinition("db_get_mitre_techniques", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: _db.get_mitre_techniques(kw.get("keywords"))))
        registry.register_tool(ToolDefinition("db_list_workflows", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: _db.list_workflows()))
        registry.register_tool(ToolDefinition("db_get_workflow", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: _db.get_workflow(kw.get("workflow_id", ""))))
        registry.register_tool(ToolDefinition("db_list_agents", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: _db.list_agents()))
        registry.register_tool(ToolDefinition("db_get_agent", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda **kw: _db.get_agent(kw.get("agent_id", ""))))
        registry.register_tool(ToolDefinition("db_get_stats", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=_db.get_stats))
    except Exception as exc:
        _skip_optional_tool_group('db_add_finding... (cyber_db)', exc)

    # --- Additional cyber_db tools ---
    try:
        from cyber_db import get_db
        _db = get_db()
        registry.register_tool(ToolDefinition("db_get_findings_count", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=_db.get_findings_count))
    except Exception as exc:
        _skip_optional_tool_group('db_get_findings_count (cyber_db)', exc)

    # --- Additional Vigil SOC tools (from cyber_soc_engine) ---
    # Workflow scaffolding
    try:
        from vigil_tools.create_workflow import build_template
        registry.register_tool(ToolDefinition("soc_create_workflow", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda workflow_id, agents="triage,investigator,responder,reporter": {"template": build_template(workflow_id, [a.strip() for a in agents.split(",")])}))
    except Exception as exc:
        _skip_optional_tool_group('soc_create_workflow (vigil_tools.create_workflow)', exc)

    # Database schema initialization
    try:
        from vigil_tools.init_schema import main as init_schema_main
        registry.register_tool(ToolDefinition("soc_init_schema", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=lambda **kw: {"status": "success"} if init_schema_main() == 0 else {"status": "failed"}))
    except Exception as exc:
        _skip_optional_tool_group('soc_init_schema (vigil_tools.init_schema)', exc)

    # Reference data seeding
    try:
        from vigil_tools.seed_reference_data import main as seed_main
        registry.register_tool(ToolDefinition("soc_seed_reference_data", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=lambda **kw: {"status": "success"} if seed_main() == 0 else {"status": "failed"}))
    except Exception as exc:
        _skip_optional_tool_group('soc_seed_reference_data (vigil_tools.seed_reference_data)', exc)

    # --- cyber_soc_engine Core Utilities ---
    # Ensure cyber_soc_engine is importable when cyber_db is unavailable
    _cyber_soc_engine_dir = None
    try:
        from pathlib import Path as _Path
        _cyber_soc_engine_dir = _Path(__file__).parent / "cyber_soc_engine"
    except Exception as exc:
        _skip_optional_tool_group('pathlib', exc)

    if _cyber_soc_engine_dir and str(_cyber_soc_engine_dir) not in sys.path:
        sys.path.insert(0, str(_cyber_soc_engine_dir))

    # Secrets management
    try:
        from cyber_soc_engine.core.secrets import get_secret, set_secret, delete_secret
        registry.register_tool(ToolDefinition("soc_get_secret", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda key, default=None: {"status": "success", "value": get_secret(key, default)}))
        registry.register_tool(ToolDefinition("soc_set_secret", ["cross_platform"], "", risk_level=RiskLevel.MODIFIES_SYSTEM, python_func=lambda key, value: {"status": "success" if set_secret(key, value) else "failed"}))
        registry.register_tool(ToolDefinition("soc_delete_secret", ["cross_platform"], "", risk_level=RiskLevel.DESTRUCTIVE, python_func=lambda key: {"status": "success" if delete_secret(key) else "failed"}))
    except Exception as exc:
        _skip_optional_tool_group('soc_get_secret... (cyber_soc_engine.core.secrets)', exc)

    # Telemetry & tracing
    try:
        from cyber_soc_engine.core.telemetry import init_telemetry, set_investigation_id, get_investigation_id
        registry.register_tool(ToolDefinition("soc_init_telemetry", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda service_name="cyber_tools": {"status": "success", "initialized": init_telemetry(service_name)}))
        registry.register_tool(ToolDefinition("soc_set_investigation_id", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda investigation_id: {"status": "success", "set": set_investigation_id(investigation_id)}))
        registry.register_tool(ToolDefinition("soc_get_investigation_id", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda: {"status": "success", "investigation_id": get_investigation_id()}))
    except Exception as exc:
        _skip_optional_tool_group('soc_init_telemetry... (cyber_soc_engine.core.telemetry)', exc)

    # Configuration
    try:
        from cyber_soc_engine.core.config import get_integration_config, is_integration_enabled, get_general_config
        registry.register_tool(ToolDefinition("soc_get_integration_config", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda integration_id: get_integration_config(integration_id)))
        registry.register_tool(ToolDefinition("soc_is_integration_enabled", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda integration_id: {"status": "success", "enabled": is_integration_enabled(integration_id)}))
        registry.register_tool(ToolDefinition("soc_get_general_config", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda key, default=None: {"status": "success", "value": get_general_config(key, default)}))
    except Exception as exc:
        _skip_optional_tool_group('soc_get_integration_config... (cyber_soc_engine.core.config)', exc)

    # Time utilities
    try:
        from cyber_soc_engine.core.time import utcnow
        registry.register_tool(ToolDefinition("soc_utcnow", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda: {"status": "success", "utcnow": utcnow().isoformat()}))
    except Exception as exc:
        _skip_optional_tool_group('soc_utcnow (cyber_soc_engine.core.time)', exc)

    # Version
    try:
        from cyber_soc_engine.core.version import _read_version
        registry.register_tool(ToolDefinition("soc_get_version", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda: {"status": "success", "version": _read_version()}))
    except Exception as exc:
        _skip_optional_tool_group('soc_get_version (cyber_soc_engine.core.version)', exc)

    # Rate limiting
    try:
        from cyber_soc_engine.core.rate_limit import get_bucket
        registry.register_tool(ToolDefinition("soc_rate_limit_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=lambda name="default", capacity=100, refill_rate=10.0, tokens=1: {"status": "simulated", "name": name, "capacity": capacity, "refill_rate": refill_rate, "tokens_requested": tokens}))
    except Exception as exc:
        _skip_optional_tool_group("soc_rate_limit_check", exc)

    # --- Generic Shell Execution (PowerShell / WSL / CMD) ---
    # Allows the AI agent to run arbitrary shell commands through the shared
    # execute_system_command infrastructure. Gated at MODIFIES_SYSTEM so the
    # guardrail layer requires operator approval for non-trivial commands.
    # If the Tools_cyber\shell_exec.py plugin is present it is also loaded
    # above via register_dynamic_cyber_tools; this direct registration
    # guarantees availability even if dynamic loading is skipped.
    try:
        from Tools_cyber.shell_exec import ShellExecTool
        _shell_exec = ShellExecTool()
        registry.register_tool(ToolDefinition(
            name=_shell_exec.name,
            environments=list(_shell_exec.environments),
            command_template="",
            requires_admin=_shell_exec.requires_admin,
            risk_level=_shell_exec.risk_level,
            fallback_tool=_shell_exec.fallback_tool,
            python_func=lambda **kwargs: _shell_exec.run(kwargs),
        ))
    except Exception as exc:
        _skip_optional_tool_group('shell_exec (Tools_cyber.shell_exec)', exc)

    # Drop-in plugins from Tools_cyber. They are registered as normal
    # ToolDefinitions so CyberAgent still applies environment routing,
    # guardrails, audit logging, fallbacks, and UI events when they execute.
    dynamic_summary = register_dynamic_cyber_tools(registry)
    for module_name, error in dynamic_summary["errors"].items():
        _skip_optional_tool_group(
            f"dynamic plugin {module_name}", RuntimeError(error)
        )

    # Registration is deliberately noisy-free: suppress(True) above stops ~140
    # "tool_registered" events. It MUST be undone here -- leaving it set discarded
    # every later audit event (tool executions, denials, guardrail rejections) for
    # the rest of the session, so audit_log.json stayed permanently empty and
    # generate_incident_report had nothing to read.
    registry.audit_logger.suppress(False)

    # --- Functional OSINT, Web Recon, Email Security, TLS, Cloud Security ---
    try:
        registry.register_tool(ToolDefinition("osint_subdomain_enum", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=OSINTRecon.enumerate_subdomains))
        registry.register_tool(ToolDefinition("osint_reverse_dns", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=OSINTRecon.reverse_dns_lookup))
        registry.register_tool(ToolDefinition("osint_dns_enum", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=OSINTRecon.dns_record_enumeration))
        registry.register_tool(ToolDefinition("osint_cloudflare_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=OSINTRecon.check_cloudflare))
        
        registry.register_tool(ToolDefinition("web_security_headers", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=WebRecon.http_headers))
        registry.register_tool(ToolDefinition("web_robots_txt", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=WebRecon.robots_txt))
        registry.register_tool(ToolDefinition("web_tech_fingerprint", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=WebRecon.tech_fingerprint))
        registry.register_tool(ToolDefinition("web_sensitive_paths", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=WebRecon.directory_listing_check))
        
        registry.register_tool(ToolDefinition("email_security_posture", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=EmailSecurityAnalyzer.email_security_posture))
        registry.register_tool(ToolDefinition("email_spf_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=EmailSecurityAnalyzer.check_spf))
        registry.register_tool(ToolDefinition("email_dmarc_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=EmailSecurityAnalyzer.check_dmarc))
        registry.register_tool(ToolDefinition("email_dkim_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=EmailSecurityAnalyzer.check_dkim))
        
        registry.register_tool(ToolDefinition("tls_cert_inspect", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=TLSAnalyzer.inspect_certificate))
        registry.register_tool(ToolDefinition("tls_config_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=TLSAnalyzer.check_tls_configuration))
        registry.register_tool(ToolDefinition("tls_ct_logs", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=TLSAnalyzer.check_certificate_transparency))
        
        registry.register_tool(ToolDefinition("cloud_s3_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=CloudSecurityChecker.check_s3_bucket))
        registry.register_tool(ToolDefinition("cloud_azure_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=CloudSecurityChecker.check_azure_blob))
        registry.register_tool(ToolDefinition("cloud_gcp_check", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=CloudSecurityChecker.check_google_bucket))
        registry.register_tool(ToolDefinition("cloud_exposed_admin", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=CloudSecurityChecker.check_exposed_admin_panels))
        
        registry.register_tool(ToolDefinition("improved_secret_scan", ["cross_platform"], "", risk_level=RiskLevel.READ_ONLY, python_func=ImprovedSecretScanner.scan_content))
    except Exception as exc:
        _skip_optional_tool_group('functional osint/web/email/tls/cloud tools', exc)

    if _OPTIONAL_TOOL_GROUPS_SKIPPED and not _SKIP_SUMMARY_REPORTED:
        # Once per process. Registration can run many times (each ToolRegistry,
        # each test), and repeating the same list every time buries real output.
        _SKIP_SUMMARY_REPORTED = True
        print(
            f"[i] {len(_OPTIONAL_TOOL_GROUPS_SKIPPED)} optional tool group(s) unavailable: "
            + "; ".join(_OPTIONAL_TOOL_GROUPS_SKIPPED)
        )
    return registry

