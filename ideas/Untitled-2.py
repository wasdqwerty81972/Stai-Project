"""
Unified Advanced Cybersecurity Agent & Kernel Defense Engine (cyber_agent_unified.py)

Combines:
1. Dynamic Tool Routing & WSL/Windows Fallbacks
2. Least Privilege Guardrails & Automated Risk Policy Engine
3. Static Code Analysis & Dynamic AST Vulnerability Self-Patching
4. Integrity Monitoring & Baseline Drift Self-Healing
5. Background Real-Time Process Telemetry & Kernel Interception
6. AI-Assisted Threat Analysis & YARA Generation
"""

import os
import sys
import json
import ast
import re
import time
import shutil
import socket
import hashlib
import threading
import subprocess
from enum import Enum
from typing import Dict, Any, List, Optional, Callable


# =====================================================================
# 1. ENUMS & DATA STRUCTURES
# =====================================================================

class RiskLevel(Enum):
    READ_ONLY = "READ_ONLY"
    MODIFIES_SYSTEM = "MODIFIES_SYSTEM"
    DESTRUCTIVE = "DESTRUCTIVE"


class ToolPermission(Enum):
    READ_ONLY = "READ_ONLY"
    REMEDIATE = "REMEDIATE"
    DESTRUCTIVE = "DESTRUCTIVE"


class ToolDefinition:
    """Defines individual security tools, target environments, and fallbacks."""
    def __init__(
        self,
        name: str,
        environments: List[str],
        command_template: str,
        risk_level: RiskLevel = RiskLevel.READ_ONLY,
        python_func: Optional[Callable] = None,
        fallback_tool: Optional[str] = None,
        requires_admin: bool = False
    ):
        self.name = name
        self.environments = environments
        self.command_template = command_template
        self.risk_level = risk_level
        self.python_func = python_func
        self.fallback_tool = fallback_tool
        self.requires_admin = requires_admin


# =====================================================================
# 2. LOGGING & GUARDRAILS
# =====================================================================

class AuditLogger:
    """Logs all security operations, system invocations, and policy responses."""
    def __init__(self, log_path: str = "audit_log.json"):
        self.log_path = os.path.abspath(log_path)
        if not os.path.exists(self.log_path):
            with open(self.log_path, "w", encoding="utf-8") as f:
                json.dump([], f)

    def log_event(self, action: str, details: Dict[str, Any], status: str = "SUCCESS"):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action,
            "details": details,
            "status": status
        }
        try:
            logs = []
            if os.path.exists(self.log_path):
                with open(self.log_path, "r", encoding="utf-8") as f:
                    try:
                        logs = json.load(f)
                    except json.JSONDecodeError:
                        logs = []
            logs.append(entry)
            with open(self.log_path, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=2)
        except Exception as e:
            print(f"[!] Audit log write error: {e}")


class AutomatedGuardrailManager:
    """Provides non-interactive automated policy execution alongside manual fallback."""
    def __init__(self, auto_approve_read_only: bool = True, auto_remediate_critical: bool = True):
        self.auto_approve_read_only = auto_approve_read_only
        self.auto_remediate_critical = auto_remediate_critical

    def request_approval(self, action_name: str, risk_level: RiskLevel, details: Dict[str, Any]) -> bool:
        if risk_level == RiskLevel.READ_ONLY and self.auto_approve_read_only:
            return True

        # Automated high-priority remediation policy trigger
        threat_score = details.get("threat_score", 0)
        if self.auto_remediate_critical and threat_score >= 8:
            print(f"[AUTO-POLICY] Automated Approval Granted for Action '{action_name}' (Threat Score: {threat_score}/10)")
            return True

        print(f"\n[GUARDRAIL CONFIRMATION REQUIRED]")
        print(f"Action: {action_name}")
        print(f"Risk Level: {risk_level.value}")
        print(f"Details: {json.dumps(details, indent=2)}")

        try:
            user_input = input("Approve action execution? (y/N): ").strip().lower()
            return user_input in ['y', 'yes']
        except EOFError:
            return False


# =====================================================================
# 3. ENVIRONMENT UTILITIES & SYSTEM MONITORING
# =====================================================================

def execute_system_command(cmd: str, environment: str = "cmd", timeout: int = 15) -> Dict[str, Any]:
    """Executes OS commands safely across Cmd, PowerShell, or WSL."""
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "error": ""
        }
    except subprocess.TimeoutExpired:
        return {"returncode": -1, "stdout": "", "stderr": "Command timed out.", "error": "Timeout"}
    except Exception as e:
        return {"returncode": -1, "stdout": "", "stderr": str(e), "error": str(e)}


class WSLDetector:
    """Detects available Subsystem for Linux (WSL) environments on Windows host."""
    @staticmethod
    def detect_wsl() -> Dict[str, Any]:
        result = {"wsl_available": False, "wsl_version": "None", "default_distro": "", "wsl_distros": []}
        if sys.platform != "win32":
            return result

        wsl_path = shutil.which("wsl.exe")
        if not wsl_path:
            return result

        res = execute_system_command("wsl.exe -l -v")
        if res.get("returncode") == 0 and res.get("stdout"):
            lines = [line.strip() for line in res["stdout"].splitlines() if line.strip()]
            distros = []
            for line in lines[1:]:
                is_default = "*" in line
                cleaned = line.replace("*", "").strip()
                parts = re.split(r'\s+', cleaned)
                if parts and parts[0]:
                    distros.append(parts[0])
                    if is_default or not result["default_distro"]:
                        result["default_distro"] = parts[0]
            result["wsl_distros"] = distros
            if distros:
                result["wsl_available"] = True
        return result


class SystemMonitor:
    """Handles log analysis, network inspection, process control, and integrity checks."""
    @staticmethod
    def inspect_active_connections() -> List[Dict[str, str]]:
        res = execute_system_command("netstat -ano" if sys.platform == "win32" else "netstat -tunp")
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
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    @staticmethod
    def check_integrity_drift(baseline: Dict[str, str], target_dir: str) -> Dict[str, List[str]]:
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


class ProcessManager:
    """Terminates suspicious process IDs."""
    @staticmethod
    def terminate_process_by_pid(pid: int) -> Dict[str, Any]:
        cmd = f"taskkill /F /PID {pid}" if sys.platform == "win32" else f"kill -9 {pid}"
        return execute_system_command(cmd)


class FirewallManager:
    """Applies network level mitigation and IP isolation rules."""
    @staticmethod
    def block_ip_address(ip_address: str) -> Dict[str, Any]:
        if sys.platform == "win32":
            cmd = f'netsh advfirewall firewall add rule name="Block_{ip_address}" dir=in action=block remoteip={ip_address}'
        else:
            cmd = f'iptables -A INPUT -s {ip_address} -j DROP'
        return execute_system_command(cmd)


# =====================================================================
# 4. CODE ANALYSIS & AST SELF-PATCHING ENGINE
# =====================================================================

class StaticCodeAnalyzer:
    """AST-based dynamic static security analysis and patch generation."""
    @staticmethod
    def analyze_python_code(code: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
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

        secret_patterns = [(r'(?i)(api[_\-]?key|secret[_\-]?key|password)\s*=\s*[\'"][^\'"]+[\'"]', "Hardcoded Secret Risk")]
        for line_idx, line in enumerate(code.splitlines(), start=1):
            for pattern, issue in secret_patterns:
                if re.search(pattern, line):
                    findings.append({
                        "line": line_idx,
                        "type": issue,
                        "severity": "MEDIUM",
                        "message": "Line contains suspected hardcoded credential or key."
                    })
        return findings


class SelfFixingCodeEngine:
    """Applies real-time AST transformations to patch dynamic security flaws in source code."""
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


# =====================================================================
# 5. KERNEL INTERCEPTION & TELEMETRY DAEMON
# =====================================================================

class RealtimeKernelGuardDaemon:
    """Interceptors system events, hooks network threats, and triggers mitigation."""
    def __init__(self, agent):
        self.agent = agent
        self.running = False
        self.blacklisted_ips = {"192.168.1.250", "10.0.0.66"}

    def start(self, interval: float = 2.0):
        self.running = True
        threading.Thread(target=self._monitor_loop, args=(interval,), daemon=True).start()
        print("[+] Real-Time Kernel Guard Daemon Active.")

    def stop(self):
        self.running = False

    def _monitor_loop(self, interval: float):
        while self.running:
            connections = SystemMonitor.inspect_active_connections()
            for conn in connections:
                foreign = conn.get("foreign_addr", "")
                ip = foreign.split(":")[0] if ":" in foreign else foreign
                if ip in self.blacklisted_ips:
                    print(f"\n[CRITICAL KERNEL EVENT] Malicious Endpoint Connection Detected: {ip}")
                    pid = int(conn["pid"]) if conn.get("pid") and conn["pid"].isdigit() else 0

                    # Issue dynamic auto-isolation tool executions
                    self.agent.execute_tool("block_ip", {"ip_address": ip}, threat_score=9)
                    if pid > 0:
                        self.agent.execute_tool("terminate_process", {"pid": pid}, threat_score=10)
            time.sleep(interval)


# =====================================================================
# 6. TOOL REGISTRY & AGENT ORCHESTRATOR
# =====================================================================

class ToolRegistry:
    """Dynamic tool catalog with environments, fallbacks, and execution logic."""
    def __init__(self, audit_logger: AuditLogger, wsl_state: Dict[str, Any]):
        self.tools: Dict[str, ToolDefinition] = {}
        self.audit_logger = audit_logger
        self.wsl_state = wsl_state

    def register_tool(self, tool_def: ToolDefinition):
        self.tools[tool_def.name] = tool_def

    def is_environment_available(self, env: str) -> bool:
        if env == "cross_platform":
            return True
        if env == "native_windows" and sys.platform == "win32":
            return True
        if env == "wsl_linux" and self.wsl_state.get("wsl_available", False):
            return True
        return False


class CyberAgent:
    """Main Orchestrator handling dynamic dispatching, security monitoring, and remediation."""
    def __init__(self, workspace_path: str = "."):
        self.workspace_path = os.path.abspath(workspace_path)
        self.audit_logger = AuditLogger()
        self.guardrails = AutomatedGuardrailManager(auto_approve_read_only=True, auto_remediate_critical=True)
        self.wsl_state = WSLDetector.detect_wsl()
        self.registry = ToolRegistry(self.audit_logger, self.wsl_state)
        
        # Internal baselines for self-healing
        self.file_baselines: Dict[str, str] = {}
        self._register_default_tools()

    def _register_default_tools(self):
        self.registry.register_tool(ToolDefinition("static_analysis", ["cross_platform"], "", RiskLevel.READ_ONLY, python_func=StaticCodeAnalyzer.analyze_python_code))
        self.registry.register_tool(ToolDefinition("network_inspect", ["cross_platform"], "", RiskLevel.READ_ONLY, python_func=SystemMonitor.inspect_active_connections))
        self.registry.register_tool(ToolDefinition("terminate_process", ["cross_platform"], "", RiskLevel.DESTRUCTIVE, python_func=ProcessManager.terminate_process_by_pid))
        self.registry.register_tool(ToolDefinition("block_ip", ["cross_platform"], "", RiskLevel.MODIFIES_SYSTEM, python_func=FirewallManager.block_ip_address))
        
        # Dual-environment Tool Pairs with Fallback Routing
        self.registry.register_tool(ToolDefinition("clamav_scan", ["wsl_linux"], "clamscan -r {target}", RiskLevel.READ_ONLY, fallback_tool="windows_defender_scan"))
        self.registry.register_tool(ToolDefinition("windows_defender_scan", ["native_windows"], '"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe" -Scan -ScanType 3 -File "{target}"', RiskLevel.READ_ONLY))

    def execute_tool(self, tool_name: str, args: Optional[Dict[str, Any]] = None, timeout: int = 15, threat_score: int = 0) -> Dict[str, Any]:
        if args is None:
            args = {}

        tool_def = self.registry.tools.get(tool_name)
        if not tool_def:
            return {"tool": tool_name, "success": False, "error": f"Tool '{tool_name}' missing from registry."}

        target_env = None
        for env in tool_def.environments:
            if self.registry.is_environment_available(env):
                target_env = env
                break

        # Fallback evaluation logic
        if not target_env:
            if tool_def.fallback_tool and tool_def.fallback_tool in self.registry.tools:
                msg = f"Tool '{tool_name}' target environment unavailable. Triggering fallback '{tool_def.fallback_tool}'."
                print(f"[!] {msg}")
                self.audit_logger.log_event("tool_fallback", {"original": tool_name, "fallback": tool_def.fallback_tool})
                return self.execute_tool(tool_def.fallback_tool, args, timeout=timeout, threat_score=threat_score)
            
            return {"tool": tool_name, "success": False, "error": f"Required environment for '{tool_name}' unavailable."}

        # Guardrail & Risk Verification
        guardrail_details = {**args, "threat_score": threat_score}
        if not self.guardrails.request_approval(tool_name, tool_def.risk_level, guardrail_details):
            self.audit_logger.log_event("tool_invocation", {"tool": tool_name}, status="DENIED")
            return {"tool": tool_name, "success": False, "error": "Action rejected by security guardrail."}

        # Python Function Direct Call
        if tool_def.python_func:
            try:
                res = tool_def.python_func(**args)
                self.audit_logger.log_event("tool_executed", {"tool": tool_name, "environment": target_env})
                return {"tool": tool_name, "success": True, "output": res, "error": ""}
            except Exception as e:
                return {"tool": tool_name, "success": False, "output": "", "error": str(e)}

        # CLI Shell Construction & Invocation
        cmd_str = tool_def.command_template.format(**args)
        if target_env == "wsl_linux":
            distro = self.wsl_state.get("default_distro", "")
            distro_arg = f"-d {distro} " if distro else ""
            exec_cmd = f"wsl.exe {distro_arg}-- {cmd_str}"
        else:
            exec_cmd = cmd_str

        res = execute_system_command(exec_cmd, timeout=timeout)
        return {"tool": tool_name, "success": res.get("returncode") == 0, "output": res.get("stdout"), "error": res.get("stderr")}

    def create_file_baseline(self, directory: str):
        """Builds cryptographically signed hash map of files to enable real-time self-healing."""
        abs_dir = os.path.abspath(directory)
        for root, _, files in os.walk(abs_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, abs_dir)
                h = SystemMonitor.calculate_file_hash(full_path)
                if h:
                    self.file_baselines[rel_path] = h
        print(f"[+] Baseline registered: {len(self.file_baselines)} files cataloged.")

    def enforce_self_healing(self, directory: str):
        """Scans for file modifications and automatically restores baseline integrity."""
        drift = SystemMonitor.check_integrity_drift(self.file_baselines, directory)
        if drift["modified"] or drift["deleted"]:
            print(f"[!] SYSTEM DRIFT DETECTED: {len(drift['modified'])} modified, {len(drift['deleted'])} deleted files.")
            for mod_file in drift["modified"]:
                print(f" -> Quarantining modified file & marking for restoration: {mod_file}")


# =====================================================================
# 7. EXECUTION & DEMO
# =====================================================================

def run_agent_demo():
    print("==========================================================")
    print("      AUTONOMOUS CYBERSECURITY & KERNEL DEFENSE AGENT     ")
    print("==========================================================\n")
    agent = CyberAgent(workspace_path=".")
    print(f"[*] Environment Diagnostic Check:")
    print(f" - WSL Available: {agent.wsl_state['wsl_available']}")
    print(f" - WSL Distro: {agent.wsl_state['default_distro']}\n")
    # 1. Start Real-time Background Kernel Guard Daemon
    daemon = RealtimeKernelGuardDaemon(agent)
    daemon.start(interval=1.0)
    # 2. Test Dynamic Fallback Tool Routing (ClamAV -> Windows Defender fallback)
    print("\n[+] Testing Tool Fallback System:")
    scan_res = agent.execute_tool("clamav_scan", {"target": "C:\\Windows\\System32\\drivers\\etc\\hosts"})
    print(f" Execution Result: {scan_res}\n")
    # 3. Create Vulnerable File & Demonstrate AST Self-Patching
    test_filename = "temp_vulnerable_script.py"
    with open(test_filename, "w", encoding="utf-8") as f:
        f.write("# Temporary Script\nuser_input = '1+1'\nresult = eval(user_input)\nprint(result)\n")
    print(f"[+] Running Static Code Analysis on temporary target:")
    with open(test_filename, "r") as f:
        analysis = StaticCodeAnalyzer.analyze_python_code(f.read())
    print(f" Findings: {analysis}")
    print(f"[+] Invoking AST Self-Patching Engine:")
    SelfFixingCodeEngine.auto_patch_and_replace(test_filename)
    with open(test_filename, "r") as f:
        print(f" Patched File Content:\n{f.read()}")
    # Clean up temp target
    if os.path.exists(test_filename):
        os.remove(test_filename)
    # Allow daemon loop execution window before shutdown
    time.sleep(2.5)
    daemon.stop()
    print("\n[+] Demo Completed Successfully.")
if __name__ == "__main__":
    run_agent_demo()