"""
CyberAgent Tool Orchestrator

Bridges the UI, Intent Router, Tool Registry, and LLM backend into a single
request pipeline:

    USER MESSAGE
        ↓
    Intent / Tool Router
        ↓
    ┌──────────────────────────────┐
    │ Normal conversation?         │──→ LLM → response
    └──────────────────────────────┘
        ↓ security/action request
    Tool selection
        ↓
    Tool execution (allowlisted registry)
        ↓
    Structured tool result
        ↓
    LLM receives tool result
        ↓
    Final explanation
        ↓
    UI

Rules:
  - Normal conversation NEVER triggers tools.
  - Security/action requests ALWAYS execute real tools.
  - LLM may REQUEST a tool, but the backend validates the tool exists,
    validates arguments, enforces timeouts, and returns structured errors.
  - API keys/credentials are loaded ONLY through key_manager.py.
  - No hardcoded API keys, no fake/demo results.
"""

from __future__ import annotations

import json
import asyncio
import os
import re
import sys
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Union

# ---------------------------------------------------------------------------
# key_manager integration — ONLY credential/LLM entry point
# ---------------------------------------------------------------------------
try:
    from key_manager import AiApi, MockRoleKeyManager
    KEY_MANAGER_AVAILABLE = True
except Exception:
    KEY_MANAGER_AVAILABLE = False
    AiApi = None
    MockRoleKeyManager = None

# ---------------------------------------------------------------------------
# Local imports — allowlisted tools and intent routing
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_os.intent_router import IntentRouter, IntentResult, IntentType
from cyber_tools import (
    ToolRegistry,
    ToolDefinition,
    RiskLevel,
    AuditLogger,
    StaticCodeAnalyzer,
    SecretScanner,
    SystemMonitor,
    register_all_default_tools,
    execute_system_command,
)
from cyber_os.nemo_agent_toolkit import NeMoAgentToolkitBridge

# UI event bus — emits structured events for the web/desktop frontends
try:
    from ui.event_bus import AgentEvent, event_bus
    _EVENT_BUS_AVAILABLE = True
except Exception:
    _EVENT_BUS_AVAILABLE = False
    AgentEvent = None
    event_bus = None

# Policy engine — centralized approval gate for security actions
try:
    from cyber_os.policy_engine import PolicyEngine
    _POLICY_AVAILABLE = True
except Exception:
    _POLICY_AVAILABLE = False
    PolicyEngine = None


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    """Represents a single tool invocation."""
    tool: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    status: str = "queued"
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: Optional[float] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None


@dataclass
class OrchestrationStep:
    """One step in the visible execution chain."""
    phase: str
    tool: Optional[str]
    input_summary: str
    output_summary: str
    status: str
    duration_ms: Optional[float] = None


@dataclass
class OrchestrationResult:
    """Final result returned to the UI."""
    success: bool
    response: str
    tool_calls: List[ToolCall] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    steps: List[OrchestrationStep] = field(default_factory=list)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Windows Defender PowerShell Adapter
# ---------------------------------------------------------------------------

class WindowsDefenderAdapter:
    """
    Executes Windows Defender scans via PowerShell / MpCmdRun.

    Uses the documented Defender interfaces:
      - Start-MpScan -ScanType CustomScan -ScanPath <path>
      - Get-MpThreat / Get-MpThreatDetection for results

    Returns structured JSON results.
    """

    @staticmethod
    def scan(path: str, scan_type: str = "CustomScan", timeout: int = 120) -> Dict[str, Any]:
        """
        Run a Defender scan against a file or folder.

        Args:
            path: File or directory path to scan.
            scan_type: QuickScan, FullScan, or CustomScan.
            timeout: Maximum seconds to wait.

        Returns:
            {
                "success": bool,
                "tool": "windows_defender_scan",
                "path": str,
                "scan_type": str,
                "threats_found": [...],
                "raw_output": str,
                "error": str | None
            }
        """
        if sys.platform != "win32":
            return {
                "success": False,
                "tool": "windows_defender_scan",
                "path": path,
                "scan_type": scan_type,
                "threats_found": [],
                "raw_output": "",
                "error": "Windows Defender scan is only available on Windows.",
            }

        if not os.path.exists(path):
            return {
                "success": False,
                "tool": "windows_defender_scan",
                "path": path,
                "scan_type": scan_type,
                "threats_found": [],
                "raw_output": "",
                "error": f"Path does not exist: {path}",
            }

        # Validate path: prevent injection, allow only normal paths
        path = os.path.normpath(path)
        if not re.match(r'^[A-Za-z]:\\', path) and not path.startswith('\\\\'):
            return {
                "success": False,
                "tool": "windows_defender_scan",
                "path": path,
                "scan_type": scan_type,
                "threats_found": [],
                "raw_output": "",
                "error": "Invalid path. Provide an absolute Windows path.",
            }

        # Check Defender availability
        defender_paths = [
            os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe"),
            os.path.expandvars(r"%ProgramFiles%\Windows Defender\MpCmdRun.exe"),
        ]
        defender_available = any(os.path.exists(p) for p in defender_paths)

        if not defender_available:
            return {
                "success": False,
                "tool": "windows_defender_scan",
                "path": path,
                "scan_type": scan_type,
                "threats_found": [],
                "raw_output": "",
                "error": "Windows Defender (MpCmdRun.exe) not found on this system.",
            }

        # Build PowerShell command using Start-MpScan
        ps_cmd = (
            "try { "
            f"$scan = Start-MpScan -ScanType {scan_type} -ScanPath '{path}' -AsJob | Wait-Job -Timeout {timeout}; "
            "$threats = @(); "
            "if ($scan) { "
            "  $threats = Get-MpThreat | ForEach-Object { "
            "    [PSCustomObject]@{ "
            "      ThreatName = $_.ThreatName; "
            "      SeverityID = $_.SeverityID; "
            "      SeverityName = $_.SeverityName; "
            "      IsActive = $_.IsActive; "
            "      DidThreatExecute = $_.DidThreatExecute; "
            "      Path = $_.Resources | ForEach-Object { $_.Resource } "
            "    } "
            "  } "
            "} "
            "$threats | ConvertTo-Json -Depth 5"
            "} catch { "
            f"Write-Output \"ERROR: $_\" "
            "}"
        )

        try:
            result = execute_system_command(
                f'powershell -NoProfile -NonInteractive -Command "{ps_cmd}"',
                environment="cmd",
                timeout=timeout + 10,
            )
        except Exception as e:
            return {
                "success": False,
                "tool": "windows_defender_scan",
                "path": path,
                "scan_type": scan_type,
                "threats_found": [],
                "raw_output": "",
                "error": f"Failed to execute Defender scan: {e}",
            }

        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        returncode = result.get("returncode", -1)

        if "ERROR:" in stdout:
            return {
                "success": False,
                "tool": "windows_defender_scan",
                "path": path,
                "scan_type": scan_type,
                "threats_found": [],
                "raw_output": stdout,
                "error": stdout.strip(),
            }

        threats = []
        try:
            # Try to parse JSON threat output
            threat_json = stdout.strip()
            if threat_json:
                parsed = json.loads(threat_json)
                if isinstance(parsed, list):
                    threats = parsed
                elif isinstance(parsed, dict):
                    threats = [parsed]
        except (json.JSONDecodeError, ValueError):
            # Defender may return empty or non-JSON when no threats
            pass

        success = returncode == 0
        return {
            "success": success,
            "tool": "windows_defender_scan",
            "path": path,
            "scan_type": scan_type,
            "threats_found": threats,
            "raw_output": stdout,
            "error": stderr if not success else None,
        }


# ---------------------------------------------------------------------------
# File / Workspace analyzers (allowlisted Python implementations)
# ---------------------------------------------------------------------------

class FileAnalyzer:
    """Analyzes a single file for security issues."""

    @staticmethod
    def analyze_file(filepath: str) -> Dict[str, Any]:
        if not os.path.isfile(filepath):
            return {"error": f"File not found: {filepath}", "findings": []}

        _, ext = os.path.splitext(filepath)
        ext = ext.lower()

        findings: List[Dict[str, Any]] = []

        if ext == ".py":
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
                findings = StaticCodeAnalyzer.analyze_python_code(code)
            except Exception as e:
                return {"error": str(e), "findings": []}

        elif ext in (".txt", ".md", ".json", ".yaml", ".yml", ".env", ".cfg", ".ini"):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                findings = SecretScanner.scan_text_for_secrets(content)
            except Exception as e:
                return {"error": str(e), "findings": []}

        elif ext in (".exe", ".dll", ".sys", ".scr"):
            findings = []  # PE analysis could be added here

        else:
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(4096)
                findings = SecretScanner.scan_text_for_secrets(content)
            except Exception as e:
                return {"error": str(e), "findings": []}

        return {
            "file": filepath,
            "extension": ext,
            "findings_count": len(findings),
            "findings": findings,
        }


class WorkspaceScanner:
    """Scans a workspace directory for security issues."""

    @staticmethod
    def scan_workspace(workspace_path: str, max_files: int = 50) -> Dict[str, Any]:
        workspace_path = os.path.abspath(workspace_path)
        if not os.path.isdir(workspace_path):
            return {"error": f"Directory not found: {workspace_path}", "findings": []}

        all_findings: List[Dict[str, Any]] = []
        scanned_files = 0
        errors = []

        for root, dirs, files in os.walk(workspace_path):
            # Skip hidden/system dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("__pycache__", "node_modules", ".git")]

            for filename in files:
                if scanned_files >= max_files:
                    break
                filepath = os.path.join(root, filename)
                try:
                    result = FileAnalyzer.analyze_file(filepath)
                    if "error" not in result:
                        for finding in result.get("findings", []):
                            finding["file"] = filepath
                            all_findings.append(finding)
                    scanned_files += 1
                except Exception as e:
                    errors.append({"file": filepath, "error": str(e)})

            if scanned_files >= max_files:
                break

        return {
            "workspace": workspace_path,
            "scanned_files": scanned_files,
            "findings_count": len(all_findings),
            "findings": all_findings,
            "errors": errors,
        }


# ---------------------------------------------------------------------------
# LLM helper — routes through key_manager ONLY
# ---------------------------------------------------------------------------

class LLMClient:
    """Thin wrapper around key_manager.AiApi."""

    def __init__(self, use_mock: bool = False):
        self.use_mock = use_mock
        self._api = None
        if KEY_MANAGER_AVAILABLE and AiApi is not None:
            try:
                self._api = AiApi(use_mock=use_mock)
            except Exception:
                self._api = None

    def chat(self, system: str, user: str, role: str = "investigator") -> str:
        if not self._api:
            return "[LLM unavailable] key_manager.py could not initialize AiApi."

        try:
            resp = self._api.chat_with_role(role, system, user, temperature=0.2, max_retries=2)
            return resp.choices[0].message.content
        except Exception as e:
            return f"[LLM error] {e}"

    def chat_json(self, system: str, user: str, role: str = "investigator") -> Dict[str, Any]:
        text = self.chat(system, user, role)
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            cleaned = text.strip()
            if cleaned.startswith("```"):
                cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE | re.DOTALL).strip()
            try:
                parsed = json.loads(cleaned)
                return parsed if isinstance(parsed, dict) else {"response": text}
            except (json.JSONDecodeError, ValueError):
                match = re.search(r"\{.*\}", cleaned, re.DOTALL)
                if match:
                    try:
                        parsed = json.loads(match.group(0))
                        return parsed if isinstance(parsed, dict) else {"response": text}
                    except (json.JSONDecodeError, ValueError):
                        pass
                return {"response": text}


# ---------------------------------------------------------------------------
# Tool Orchestrator — the main backend the UI talks to
# ---------------------------------------------------------------------------

class ToolOrchestrator:
    """
    Central backend for the CyberAgent workspace.

    Responsibilities:
      1. Classify user intent.
      2. For normal conversation: call LLM, return text.
      3. For security requests: use the model to select tool(s), execute them, collect results,
         send results to LLM for explanation, return final response + findings.
      4. Emit structured steps for the Activity panel.
      5. Convert tool results into the standard Finding format.
    """

    def __init__(self, workspace_path: str = ".", use_mock_llm: bool = False, max_tool_calls: int = 4, agent: Any = None):
        self.workspace_path = os.path.abspath(workspace_path)
        self.audit_logger = AuditLogger()
        self.registry = ToolRegistry(self.audit_logger)
        register_all_default_tools(self.registry)
        self._register_custom_tools()
        self.llm = LLMClient(use_mock=use_mock_llm)
        self.router = IntentRouter()
        self.max_tool_calls = max(1, max_tool_calls)
        self.agent = agent
        self._tool_calls_used: List[str] = []
        self.nat = NeMoAgentToolkitBridge(self.tool_manifest(), self.workspace_path)
        from cyber_os.investigation_state import InvestigationState
        self.investigation_state = InvestigationState(os.path.join(workspace_path, ".investigations"))
        self.current_investigation = None
        self.current_session_id = "default"

        # Policy engine — centralized approval gate for security actions
        if _POLICY_AVAILABLE and PolicyEngine is not None:
            try:
                self.policy_engine = PolicyEngine(storage_path=os.path.join(workspace_path, "cyber_os", "policies.json"))
            except Exception:
                self.policy_engine = None
        else:
            self.policy_engine = None

    def _map_tool_to_action_type(self, tool_name: str) -> str:
        """Map a registered tool name to a policy action_type."""
        mapping = {
            "terminate_process": "terminate_process",
            "quarantine_file": "quarantine_file",
            "block_ip": "block_ip",
            "disable_persistence": "disable_persistence",
            "disable_account": "disable_account",
            "remove_ssh_key": "remove_ssh_key",
            "read_processes": "read_processes",
            "read_network": "read_network",
            "scan_system": "scan_system",
            "investigate": "investigate",
        }
        if tool_name in mapping:
            return mapping[tool_name]
        # Default: read-only tools map to "investigate"; mutating tools need approval
        tool_def = self.registry.tools.get(tool_name)
        if tool_def is not None and tool_def.risk_level == RiskLevel.READ_ONLY:
            return "investigate"
        return tool_name

    def _gate_action(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Run a tool invocation through the policy engine.

        Returns a decision dict with at least:
            allowed, requires_approval, auto_approved, policy_id, reason
        """
        if self.policy_engine is None:
            return {"allowed": True, "requires_approval": False, "auto_approved": True, "policy_id": None, "reason": "No policy engine configured."}

        action_type = self._map_tool_to_action_type(tool_name)
        tool_def = self.registry.tools.get(tool_name)
        risk_score = 0.0
        if tool_def is not None:
            try:
                risk_score = float(tool_def.risk_level.value)
            except Exception:
                risk_score = 0.0
        return self.policy_engine.gate_action(
            action_type=action_type,
            risk_score=risk_score,
            tool_name=tool_name,
            arguments=args,
            details={"workspace": self.workspace_path},
        )

    def tool_manifest(self) -> List[Dict[str, Any]]:
        """Return the allowlisted tool catalog exposed to the model."""
        return [tool.to_manifest() for tool in self.registry.tools.values()]

    def nat_status(self) -> Dict[str, Any]:
        """Return optional NAT integration status for the UI and diagnostics."""
        return self.nat.status()

    # ------------------------------------------------------------------
    # Custom tool registration (Python functions not in cyber_tools)
    # ------------------------------------------------------------------

    def _register_custom_tools(self):
        """Register Python-based tools that live in this orchestrator."""
        from cyber_tools import _list_workspace_files, _read_workspace_file

        self.registry.register_tool(ToolDefinition(
            name="workspace_list_files",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=lambda root=self.workspace_path, pattern="*", max_results=200: _list_workspace_files(root, pattern, max_results),
        ))
        self.registry.register_tool(ToolDefinition(
            name="workspace_read_file",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=lambda filepath="", max_bytes=200000: _read_workspace_file(filepath, max_bytes),
        ))
        self.registry.register_tool(ToolDefinition(
            name="windows_defender_scan",
            environments=["native_windows"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=lambda path="", scan_type="CustomScan", timeout=120: (
                WindowsDefenderAdapter.scan(path=path, scan_type=scan_type, timeout=timeout)
            ),
        ))

        self.registry.register_tool(ToolDefinition(
            name="static_analysis",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=lambda code="", filepath="": self._run_static_analysis(code=code, filepath=filepath),
        ))

        self.registry.register_tool(ToolDefinition(
            name="secret_scan",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=lambda content="", filepath="": self._run_secret_scan(content=content, filepath=filepath),
        ))

        self.registry.register_tool(ToolDefinition(
            name="file_analyze",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=lambda filepath="": FileAnalyzer.analyze_file(filepath=filepath),
        ))

        self.registry.register_tool(ToolDefinition(
            name="workspace_scan",
            environments=["cross_platform"],
            command_template="",
            risk_level=RiskLevel.READ_ONLY,
            python_func=lambda workspace_path="", max_files=50: WorkspaceScanner.scan_workspace(
                workspace_path=workspace_path, max_files=max_files
            ),
        ))

    @staticmethod
    def _run_static_analysis(code: str = "", filepath: str = "") -> Dict[str, Any]:
        if filepath and os.path.isfile(filepath):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
            except Exception as e:
                return {"error": str(e), "findings": []}
        if not code:
            return {"error": "No code provided for static analysis.", "findings": []}
        findings = StaticCodeAnalyzer.analyze_python_code(code)
        return {"findings": findings, "findings_count": len(findings)}

    @staticmethod
    def _run_secret_scan(content: str = "", filepath: str = "") -> Dict[str, Any]:
        if filepath and os.path.isfile(filepath):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                return {"error": str(e), "findings": []}
        if not content:
            return {"error": "No content provided for secret scan.", "findings": []}
        findings = SecretScanner.scan_text_for_secrets(content)
        return {"findings": findings, "findings_count": len(findings)}

    # ------------------------------------------------------------------
    # Main entry point — called by the UI
    # ------------------------------------------------------------------

    def handle_message(self, user_input: str, session_id: str = "default") -> OrchestrationResult:
        """
        Process a user message end-to-end and return the result for the UI.

        This is the single entry point the UI should call.
        """
        steps: List[OrchestrationStep] = []
        tool_calls: List[ToolCall] = []
        self._tool_calls_used = []
        evidence_context = ""

        # Create investigation context for this request
        self.current_investigation = self.investigation_state.create(
            objective=user_input[:200],
            session_id=session_id,
        )

        # Emit investigation_started event
        if _EVENT_BUS_AVAILABLE and event_bus is not None:
            event_bus.publish(AgentEvent(
                type="investigation_started",
                session_id=session_id,
                investigation_id=self.current_investigation["investigation_id"],
                message=f"Investigation started: {user_input[:80]}",
                data={"objective": user_input[:200], "tool_calls_planned": 0},
            ))

        # 1. Classify intent
        intent_result = self.router.classify(user_input)
        steps.append(OrchestrationStep(
            phase="intent_classification",
            tool=None,
            input_summary=user_input[:120],
            output_summary=f"intent={intent_result.intent.value} confidence={intent_result.confidence:.2f}",
            status="completed",
        ))

        # 2. Normal conversation / informational → LLM only, NO tools
        if intent_result.intent in (IntentType.CONVERSATIONAL, IntentType.INFORMATIONAL):
            response = self.llm.chat(
                system="You are a helpful cybersecurity assistant. Be concise and friendly.",
                user=user_input,
                role="investigator",
            )
            steps.append(OrchestrationStep(
                phase="llm_response",
                tool=None,
                input_summary=user_input[:120],
                output_summary=response[:200],
                status="completed",
            ))
            return OrchestrationResult(
                success=True,
                response=response,
                tool_calls=tool_calls,
                steps=steps,
            )

        # 3. Unknown intent → ask for clarification, no tools
        if intent_result.intent == IntentType.UNKNOWN:
            clarification = intent_result.clarification or (
                "I can help with security analysis. Try: 'scan I:\\ drive', "
                "'analyze main.py', 'find secrets in this workspace', or 'investigate this system'."
            )
            steps.append(OrchestrationStep(
                phase="clarification",
                tool=None,
                input_summary=user_input[:120],
                output_summary=clarification[:200],
                status="completed",
            ))
            return OrchestrationResult(
                success=True,
                response=clarification,
                tool_calls=tool_calls,
                steps=steps,
            )

        # 4. Security / action request → iterate through relevant tools until the
        #    next step no longer adds evidence to the investigation.
        all_findings = []
        while len(tool_calls) < self.max_tool_calls:
            tool_name = self._select_tool(user_input, intent_result, evidence_context)
            if not tool_name:
                response = (
                    "I couldn't determine which tool to use for that request. "
                    "Try being more specific, e.g. 'scan I:\\ drive' or 'analyze main.py'."
                )
                steps.append(OrchestrationStep(
                    phase="tool_selection_failed",
                    tool=None,
                    input_summary=user_input[:120],
                    output_summary="No matching tool found",
                    status="failed",
                ))
                return OrchestrationResult(
                    success=False,
                    response=response,
                    tool_calls=tool_calls,
                    steps=steps,
                    error="No matching tool",
                )

            if tool_name in self._tool_calls_used:
                break

            args = self._build_tool_args(tool_name, user_input)
            tool_call = self._execute_tool(tool_name, args)
            self._tool_calls_used.append(tool_name)
            tool_calls.append(tool_call)
            
            # Save tool call to investigation state
            self.investigation_state.append_event(
                self.current_investigation["investigation_id"],
                {
                    "type": "tool_executed",
                    "tool": tool_name,
                    "arguments": args,
                    "status": tool_call.status,
                    "timestamp": datetime.now().isoformat(),
                }
            )
            tool_output = (tool_call.result or {}).get("raw_output") if tool_call.result else None
            if tool_output is None and tool_call.result:
                tool_output = (tool_call.result or {}).get("output", "")
            tool_output = str(tool_output or tool_call.error or "")
            steps.append(OrchestrationStep(
                phase="tool_execution",
                tool=tool_name,
                input_summary=str(args)[:200],
                output_summary=tool_output[:200],
                status=tool_call.status,
                duration_ms=tool_call.duration_ms,
            ))

            findings = self._result_to_findings(tool_call)
            all_findings.extend(findings)
            evidence_context = self._summarize_evidence(tool_call, findings)
            
            # Save findings to investigation state
            for finding in findings:
                self.investigation_state.append_event(
                    self.current_investigation["investigation_id"],
                    {
                        "type": "finding",
                        "tool": tool_name,
                        "severity": finding.get("severity", "unknown"),
                        "title": finding.get("title", ""),
                        "timestamp": datetime.now().isoformat(),
                    }
                )
                # Emit finding_created event for the UI findings panel
                if _EVENT_BUS_AVAILABLE and event_bus is not None:
                    event_bus.publish(AgentEvent(
                        type="finding_created",
                        session_id=getattr(self, "current_session_id", "default"),
                        investigation_id=self.current_investigation["investigation_id"],
                        tool=tool_name,
                        status="created",
                        message=f"Finding: {finding.get('title', 'Unknown')}",
                        data={
                            "finding": finding,
                            "tool": tool_name,
                            "severity": finding.get("severity", "unknown"),
                            "title": finding.get("title", ""),
                            "file": finding.get("file", ""),
                            "line": finding.get("line"),
                            "mitre_id": finding.get("mitre_id", ""),
                            "recommendation": finding.get("recommendation", ""),
                        },
                    ))
                    # Emit evidence_added event for the evidence abstraction panel
                    event_bus.publish(AgentEvent(
                        type="evidence_added",
                        session_id=getattr(self, "current_session_id", "default"),
                        investigation_id=self.current_investigation["investigation_id"],
                        tool=tool_name,
                        status="added",
                        message=f"Evidence added for {finding.get('title', 'Unknown')}",
                        data={
                            "tool": tool_name,
                            "finding_title": finding.get("title", ""),
                            "severity": finding.get("severity", "unknown"),
                            "file": finding.get("file", ""),
                            "line": finding.get("line"),
                            "evidence": finding.get("evidence", ""),
                            "source": finding.get("source", tool_name),
                        },
                    ))

            llm_prompt = self._build_llm_prompt(user_input, tool_call, findings)
            llm_response = self.llm.chat(
                system=(
                    "You are a cybersecurity agent. "
                    "Explain the tool result to the user in plain language. "
                    "If threats were found, list them with severity. "
                    "If none were found, say so clearly. "
                    "If there was an error, explain what happened and suggest next steps. "
                    "Do NOT claim a scan ran unless the tool result confirms it."
                ),
                user=llm_prompt,
                role="incident_responder",
            )
            if len(tool_calls) == 1:
                steps.append(OrchestrationStep(
                    phase="llm_explanation",
                    tool=None,
                    input_summary=f"Tool result: {(tool_call.result or {}).get('raw_output', '')[:120]}",
                    output_summary=llm_response[:200],
                    status="completed",
                ))

            if not self._should_continue_investigation(tool_call, findings):
                break

            if len(tool_calls) >= self.max_tool_calls:
                break

        final_tool_call = tool_calls[-1] if tool_calls else None
        final_findings = all_findings
        final_response = self.llm.chat(
            system=(
                "You are a cybersecurity agent. Summarize the investigation outcome using the evidence collected so far. "
                "Be direct, evidence-based, and concise."
            ),
            user=(
                f"User request: {user_input}\n\n"
                f"Investigation summary:\n{evidence_context or 'No additional evidence gathered.'}\n\n"
                f"Key findings: {json.dumps(final_findings[:5], default=str)}"
            ),
            role="incident_responder",
        )
        
        # Mark investigation complete
        success = final_tool_call is not None and final_tool_call.status == "completed"
        if self.current_investigation:
            self.current_investigation["status"] = "completed"
            self.current_investigation["findings"] = final_findings
            self.investigation_state.save(self.current_investigation)
            if _EVENT_BUS_AVAILABLE and event_bus is not None:
                event_bus.publish(AgentEvent(
                    type="investigation_completed",
                    session_id=getattr(self, "current_session_id", "default"),
                    investigation_id=self.current_investigation["investigation_id"],
                    status="completed",
                    message=f"Investigation completed: {len(final_findings)} finding(s), {len(tool_calls)} tool call(s)",
                    data={
                        "investigation_id": self.current_investigation["investigation_id"],
                        "tool_calls": len(tool_calls),
                        "findings_count": len(final_findings),
                        "findings": final_findings,
                        "success": success,
                    },
                ))

        if not tool_calls:
            return OrchestrationResult(
                success=False,
                response="I did not find a valid tool to execute for that request.",
                tool_calls=tool_calls,
                steps=steps,
                error="No tools executed",
            )

        return OrchestrationResult(
            success=success,
            response=final_response,
            tool_calls=tool_calls,
            findings=final_findings,
            steps=steps,
            error=final_tool_call.error if final_tool_call and final_tool_call.error else None,
        )

    # ------------------------------------------------------------------
    # Tool selection
    # ------------------------------------------------------------------

    def _select_tool(self, user_input: str, intent_result: IntentResult, investigation_context: str = "") -> Optional[str]:
        """Ask the live model to choose one registered tool, then validate it."""
        catalog = json.dumps(self.tool_manifest(), separators=(",", ":"))
        context_block = f"\nInvestigation context: {investigation_context}\n" if investigation_context else ""
        plan = self.llm.chat_json(
            system=(
                "You are the tool planner for a defensive cybersecurity agent. "
                "Choose exactly one tool from the supplied allowlist based on the user's objective. "
                'Return JSON only: {"tool": string, "arguments": object, "reason": string}. '
                "Never invent a tool name. Prefer read-only tools. "
                "If evidence has already been gathered, choose the next most relevant tool to validate or expand the investigation."
            ),
            user=f"User objective: {user_input}\nIntent hint: {intent_result.intent.value}{context_block}Allowlisted tools: {catalog}",
            role="investigator",
        )
        selected = plan.get("tool") if isinstance(plan, dict) else None
        if selected in self.registry.tools:
            self._planned_arguments = plan.get("arguments", {}) if isinstance(plan.get("arguments", {}), dict) else {}
            self._planning_reason = str(plan.get("reason", "The selected tool best matches the request."))
            return selected
        self._planned_arguments = {}
        self._planning_reason = "The model did not return a valid allowlisted tool."
        return None

    def _summarize_evidence(self, tool_call: ToolCall, findings: List[Dict[str, Any]]) -> str:
        """Create concise evidence context the model can use for the next iteration."""
        result = tool_call.result or {}
        findings_summary = []
        for item in findings[:5]:
            findings_summary.append(f"{item.get('severity', 'unknown').upper()}: {item.get('title', 'Finding')}")

        raw_output = str(result.get("raw_output") or result.get("output") or "")
        evidence_bits = [f"Tool: {tool_call.tool}", f"Status: {tool_call.status}"]
        if findings_summary:
            evidence_bits.append("Findings: " + "; ".join(findings_summary))
        elif raw_output:
            evidence_bits.append(f"Output: {raw_output[:300]}")
        if tool_call.error:
            evidence_bits.append(f"Error: {tool_call.error}")
        return " | ".join(evidence_bits)

    def _should_continue_investigation(self, tool_call: ToolCall, findings: List[Dict[str, Any]]) -> bool:
        """Return True when a fresh tool result suggests the investigation should continue."""
        if tool_call.status != "completed":
            return False

        result = self._decode_result(tool_call.result)
        if result.get("threats_found") or result.get("findings") or result.get("findings_count", 0) > 0:
            return True

        if findings:
            return True

        if tool_call.tool in {"workspace_scan", "static_analysis", "secret_scan", "windows_defender_scan"}:
            return False

        return False

    # ------------------------------------------------------------------
    # Argument building
    # ------------------------------------------------------------------

    def _build_tool_args(self, tool_name: str, user_input: str) -> Dict[str, Any]:
        """Extract arguments for the selected tool from the user input."""
        args: Dict[str, Any] = dict(getattr(self, "_planned_arguments", {}))

        if tool_name == "nmap_scan":
            args.setdefault("target", "127.0.0.1")

        if tool_name == "windows_defender_scan":
            # Extract path: look for drive letters or explicit paths
            # Patterns: "scan I:\ drive", "scan I:\", "scan C:\Users\..."
            path_match = re.search(r'([A-Za-z]:[\\/]?[^\s]*)', user_input)
            if not path_match:
                # Fallback: "scan I: drive" -> I:\
                drive_match = re.search(r'([A-Za-z])\s*[:;]|\b([A-Za-z])\s+drive\b', user_input, re.IGNORECASE)
                if drive_match:
                    drive = drive_match.group(1) or drive_match.group(2)
                    args["target"] = f"{drive.upper()}:\\"
                    args["scan_type"] = "CustomScan"
                else:
                    args["target"] = self.workspace_path
                    args["scan_type"] = "CustomScan"
            else:
                target = path_match.group(1).rstrip(';,')
                if re.fullmatch(r"[A-Za-z]:", target):
                    target += "\\"
                args["target"] = target
                args["scan_type"] = "CustomScan"
            args["timeout"] = 120

        elif tool_name == "static_analysis":
            # "analyze main.py" → resolve filepath
            file_match = re.search(r'analyze\s+(\S+\.py)', user_input, re.IGNORECASE)
            if file_match:
                candidate = file_match.group(1)
                if os.path.isabs(candidate):
                    args["filepath"] = candidate
                else:
                    args["filepath"] = os.path.join(self.workspace_path, candidate)
            else:
                args["filepath"] = self.workspace_path

        elif tool_name == "secret_scan":
            args["filepath"] = self.workspace_path

        elif tool_name == "file_analyze":
            file_match = re.search(r'(?:analyze|check|scan)\s+(?:this\s+)?(?:file\s+)?(\S+)', user_input, re.IGNORECASE)
            if file_match:
                candidate = file_match.group(1)
                if os.path.isabs(candidate):
                    args["filepath"] = candidate
                else:
                    args["filepath"] = os.path.join(self.workspace_path, candidate)
            else:
                args["filepath"] = self.workspace_path

        elif tool_name == "workspace_scan":
            args["workspace_path"] = self.workspace_path
            args["max_files"] = 50

        elif tool_name == "workspace_list_files":
            args["root"] = self.workspace_path
            args.setdefault("pattern", "*")
            args.setdefault("max_results", 200)

        elif tool_name == "workspace_read_file":
            candidate = args.get("filepath") or args.get("path")
            if not candidate:
                match = re.search(r"(?:read|open|inspect|analyze)\s+(?:file\s+)?[\"']?([^\"'\s]+)", user_input, re.IGNORECASE)
                candidate = match.group(1) if match else ""
            args["filepath"] = candidate
            args.setdefault("max_bytes", 200000)

        return args

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    def _execute_tool(self, tool_name: str, args: Dict[str, Any]) -> ToolCall:
        """Execute a tool and return a ToolCall record."""
        call = ToolCall(tool=tool_name, arguments=args, status="queued")
        call.started_at = datetime.now().isoformat()
        start = time.perf_counter()

        # Emit tool_started event BEFORE execution so the UI can render the card
        if _EVENT_BUS_AVAILABLE and event_bus is not None:
            event_bus.publish(AgentEvent(
                type="tool_started",
                session_id=getattr(self, "current_session_id", "default"),
                investigation_id=self.current_investigation["investigation_id"] if self.current_investigation else "",
                tool=tool_name,
                status="running",
                message=f"Tool {tool_name} started",
                data={
                    "tool": tool_name,
                    "arguments": args,
                    "started_at": call.started_at,
                    "risk_level": self.registry.tools[tool_name].risk_level.value if tool_name in self.registry.tools else "unknown",
                },
            ))

        # Policy gate — centralized approval for mutating actions
        if self.policy_engine is not None:
            decision = self._gate_action(tool_name, args)
            if not decision.get("allowed", True):
                call.status = "blocked"
                call.error = decision.get("reason", "Action blocked by policy.")
                if _EVENT_BUS_AVAILABLE and event_bus is not None:
                    event_bus.publish(AgentEvent(
                        type="tool_blocked",
                        session_id=getattr(self, "current_session_id", "default"),
                        investigation_id=self.current_investigation["investigation_id"] if self.current_investigation else "",
                        tool=tool_name,
                        status="blocked",
                        message=f"Tool {tool_name} blocked by policy {decision.get('policy_id', 'unknown')}",
                        data={"tool": tool_name, "decision": decision},
                    ))
                return call

            if decision.get("requires_approval") and not decision.get("auto_approved"):
                approved = self._request_approval(tool_name, args, decision)
                if _EVENT_BUS_AVAILABLE and event_bus is not None:
                    event_bus.publish(AgentEvent(
                        type="approval_granted" if approved else "approval_denied",
                        session_id=getattr(self, "current_session_id", "default"),
                        investigation_id=self.current_investigation["investigation_id"] if self.current_investigation else "",
                        tool=tool_name,
                        status="granted" if approved else "denied",
                        message=f"Approval {'granted' if approved else 'denied'} for {tool_name}",
                        data={"tool": tool_name, "decision": decision},
                    ))
                if not approved:
                    call.status = "blocked"
                    call.error = "User denied the action via the approval card."
                    return call

        try:
            res = self._execute_via_nat(tool_name, args)
            elapsed_ms = (time.perf_counter() - start) * 1000
            call.duration_ms = elapsed_ms
            call.finished_at = datetime.now().isoformat()

            if res.get("success"):
                call.status = "completed"
                call.result = res
            else:
                call.status = "failed"
                call.error = res.get("error") or res.get("stderr") or "Tool execution failed."
                call.result = res
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            call.duration_ms = elapsed_ms
            call.finished_at = datetime.now().isoformat()
            call.status = "failed"
            call.error = str(e)

        # Emit tool_completed / tool_failed event AFTER execution
        if _EVENT_BUS_AVAILABLE and event_bus is not None:
            event_bus.publish(AgentEvent(
                type="tool_completed" if call.status == "completed" else "tool_failed",
                session_id=getattr(self, "current_session_id", "default"),
                investigation_id=self.current_investigation["investigation_id"] if self.current_investigation else "",
                tool=tool_name,
                status=call.status,
                message=f"Tool {tool_name} {call.status}",
                data={
                    "tool": tool_name,
                    "arguments": args,
                    "result": call.result,
                    "error": call.error,
                    "duration_ms": call.duration_ms,
                    "started_at": call.started_at,
                    "finished_at": call.finished_at,
                },
            ))

        return call

    def _request_approval(self, tool_name: str, args: Dict[str, Any], decision: Dict[str, Any]) -> bool:
        """Publish an approval_requested event and block until the UI responds.

        Falls back to the parent agent's approval registry when present so the
        desktop shell and web UI both work. Times out after 300 s.
        """
        import uuid
        request_id = str(uuid.uuid4())
        details = {
            "tool": tool_name,
            "arguments": args,
            "policy_id": decision.get("policy_id"),
            "reason": decision.get("reason"),
            "risk_score": decision.get("risk_score"),
        }

        if _EVENT_BUS_AVAILABLE and event_bus is not None:
            event_bus.publish(AgentEvent(
                type="approval_requested",
                session_id=getattr(self, "current_session_id", "default"),
                investigation_id=self.current_investigation["investigation_id"] if self.current_investigation else "",
                tool=tool_name,
                status="pending",
                message=f"Approval required for {tool_name}",
                data={
                    "request_id": request_id,
                    "action": tool_name,
                    "risk_level": str(decision.get("risk_score", "")),
                    "details": details,
                },
            ))

        # Delegate to the parent agent's approval registry if available
        if self.agent is not None and hasattr(self.agent, "_wait_for_approval"):
            try:
                return bool(self.agent._wait_for_approval(tool_name, decision.get("risk_score", 0), details))
            except Exception:
                return False

        # No UI connected — default to deny for safety
        return False

    def _execute_via_nat(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Invoke an allowlisted registry tool through NAT's typed function API."""
        if self.agent is None:
            raise RuntimeError(
                f"Cannot execute '{tool_name}': this ToolOrchestrator was built without a "
                "CyberAgent executor. Construct it as ToolOrchestrator(..., agent=<CyberAgent>)."
            )

        async def invoke() -> Dict[str, Any]:
            from nat.builder.function import LambdaFunction
            from nat.builder.function_info import FunctionInfo
            from nat.data_models.function import FunctionBaseConfig

            async def registry_call(value: dict[str, object]) -> dict[str, object]:
                return self.agent.execute_tool(tool_name, value, timeout=120)

            info = FunctionInfo.from_fn(
                registry_call,
                description=f"Cyber defense tool: {tool_name}",
            )
            function = LambdaFunction.from_info(
                config=FunctionBaseConfig(name=f"cyber_{tool_name}"),
                info=info,
                instance_name=f"cyber_{tool_name}",
            )
            return await function.ainvoke(args)

        try:
            return asyncio.run(invoke())
        except ImportError as exc:
            # NAT is an optional dependency. Losing it must not disable the whole
            # tool catalog, so fall back to the same call NAT would have wrapped.
            print(f"[!] NAT unavailable ({exc}); executing {tool_name} directly.")
            return self.agent.execute_tool(tool_name, args, timeout=120)

    # ------------------------------------------------------------------
    # Result → Findings conversion
    # ------------------------------------------------------------------

    # Keys CyberAgent.execute_tool wraps every tool result in.
    _RESULT_ENVELOPE_KEYS = frozenset({"tool", "environment_used", "success", "output", "error"})

    @classmethod
    def _decode_result(cls, result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Lift a tool's JSON-encoded `output` into structured keys on the result.

        CyberAgent.execute_tool returns {tool, success, output, ...} where `output`
        is a JSON *string*. The converters below read structured keys such as
        `findings` straight off the result, so without this step every real tool
        result yielded zero findings -- the agent reported clean on code that had
        confirmed issues. Tests that stub _execute_tool return the already-decoded
        shape, which is why this went unnoticed.
        """
        if not isinstance(result, dict):
            return {}
        output = result.get("output")
        if not isinstance(output, str) or not output.strip():
            return result
        try:
            decoded = json.loads(output)
        except (json.JSONDecodeError, ValueError):
            return result  # plain-text tool output, nothing to lift
        if isinstance(decoded, list):
            return {**result, "findings": decoded}
        if isinstance(decoded, dict):
            # The envelope wins on its own keys; everything else is promoted.
            extra = {k: v for k, v in decoded.items() if k not in cls._RESULT_ENVELOPE_KEYS}
            return {**result, **extra}
        return result

    def _result_to_findings(self, tool_call: ToolCall) -> List[Dict[str, Any]]:
        """Convert tool result into the standard finding format."""
        findings: List[Dict[str, Any]] = []
        if tool_call.status != "completed" or not tool_call.result:
            return findings

        result = self._decode_result(tool_call.result)
        output = result.get("output", "") or result.get("raw_output", "")

        # Defender threats
        if tool_call.tool == "windows_defender_scan":
            for threat in result.get("threats_found", []):
                findings.append({
                    "severity": "critical",
                    "title": threat.get("ThreatName", "Unknown Threat"),
                    "description": f"Windows Defender detected a threat: {threat.get('ThreatName')}",
                    "source": "windows_defender",
                    "file": threat.get("Path", [""])[0] if isinstance(threat.get("Path"), list) else threat.get("Path", ""),
                    "line": None,
                    "mitre_id": "",
                    "evidence": json.dumps(threat, indent=2),
                    "recommendation": "Quarantine the file and investigate the source.",
                })

        # Static analysis findings
        elif tool_call.tool == "static_analysis":
            for f in result.get("findings", []):
                findings.append({
                    "severity": f.get("severity", "medium").lower(),
                    "title": f.get("message", f.get("type", "Unknown Issue")),
                    "description": f.get("message", ""),
                    "source": "static_analysis",
                    "file": tool_call.arguments.get("filepath", ""),
                    "line": f.get("line"),
                    "mitre_id": "",
                    "evidence": json.dumps(f, indent=2),
                    "recommendation": f.get("type", "Review and remediate."),
                })

        # Secret scan findings
        elif tool_call.tool == "secret_scan":
            for f in result.get("findings", []):
                findings.append({
                    "severity": "critical",
                    "title": f"Exposed {f.get('type', 'Secret')}",
                    "description": f"A {f.get('type', 'secret')} was detected in scanned content.",
                    "source": "secret_scanner",
                    "file": "",
                    "line": f.get("line"),
                    "mitre_id": "T1552",
                    "evidence": json.dumps(f, indent=2),
                    "recommendation": "Remove the secret from source code and rotate the credential immediately.",
                })

        # Workspace scan findings
        elif tool_call.tool == "workspace_scan":
            for f in result.get("findings", []):
                findings.append({
                    "severity": f.get("severity", "medium").lower(),
                    "title": f.get("message", f.get("type", "Workspace Finding")),
                    "description": f.get("message", ""),
                    "source": "workspace_scanner",
                    "file": f.get("file", ""),
                    "line": f.get("line"),
                    "mitre_id": "",
                    "evidence": json.dumps(f, indent=2),
                    "recommendation": "Review the flagged item in the workspace.",
                })

        return findings

    # ------------------------------------------------------------------
    # LLM prompt construction
    # ------------------------------------------------------------------

    def _build_llm_prompt(self, user_input: str, tool_call: ToolCall, findings: List[Dict[str, Any]]) -> str:
        """Build the prompt sent to the LLM after tool execution."""
        lines = [f"User request: {user_input}", ""]
        lines.append(f"Tool executed: {tool_call.tool}")
        lines.append(f"Tool status: {tool_call.status}")
        lines.append(f"Duration: {tool_call.duration_ms:.1f}ms" if tool_call.duration_ms else "Duration: unknown")
        lines.append("")

        if tool_call.error:
            lines.append(f"Tool error: {tool_call.error}")
            lines.append("Explain to the user what went wrong and suggest how to fix it.")

        if tool_call.result:
            result = tool_call.result
            raw = result.get("raw_output", "") or result.get("output", "")
            if raw:
                lines.append(f"Tool raw output:\n{raw[:2000]}")
            threats = result.get("threats_found", [])
            if threats:
                lines.append(f"\nThreats detected: {len(threats)}")
                for t in threats[:10]:
                    lines.append(f"  - {t.get('ThreatName', 'Unknown')}")

        if findings:
            lines.append(f"\nStructured findings ({len(findings)}):")
            for f in findings[:20]:
                lines.append(f"  [{f['severity'].upper()}] {f['title']}")
                lines.append(f"    File: {f.get('file', 'N/A')}")
                lines.append(f"    Recommendation: {f.get('recommendation', '')}")

        lines.append("")
        lines.append("Provide a clear summary for the user based ONLY on the actual tool results above.")
        return "\n".join(lines)
