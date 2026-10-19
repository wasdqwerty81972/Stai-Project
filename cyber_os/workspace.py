"""
CyberOS Agent Workspace UI
Modern three-column agent workspace built with customtkinter
"""

import os
import sys
import json
import time
import queue
import threading
import tkinter as tk
from tkinter import ttk
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import customtkinter as ctk

from cyber_os.agent_bus import AgentEventBus, Session, SessionManager, EventType, AgentEvent
from cyber_os.intent_router import IntentRouter, IntentType, IntentResult
from cyber_os.tool_orchestrator import ToolOrchestrator

# Theme configuration
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

COLORS = {
    "bg_primary": "#0D1117",
    "bg_secondary": "#161B22",
    "bg_panel": "#21262D",
    "border": "#30363D",
    "text_primary": "#E6EDF3",
    "text_secondary": "#8B949E",
    "accent": "#58A6FF",
    "success": "#3FB950",
    "warning": "#D29922",
    "critical": "#F85149",
    "high": "#FF8A3D",
    "medium": "#D29922",
    "low": "#58A6FF",
    "info": "#58A6FF",
}

SEVERITY_COLORS = {
    "CRITICAL": COLORS["critical"],
    "HIGH": COLORS["high"],
    "MEDIUM": COLORS["medium"],
    "LOW": COLORS["low"],
    "INFO": COLORS["info"],
}


class ScrollableText(ctk.CTkTextbox):
    """Custom scrollable text widget with tag-based coloring."""

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(
            font=("Segoe UI", 11),
            wrap="word",
            fg_color=COLORS["bg_primary"],
            text_color=COLORS["text_primary"],
            border_width=0,
        )

    def append(self, text: str, tag: str = None):
        self.insert("end", text, tag)
        self.see("end")


class ToolExecutionCard(ctk.CTkFrame):
    """Expandable tool execution card."""

    def __init__(self, master, tool_name: str, status: str = "running", **kwargs):
        super().__init__(master, **kwargs)
        self.configure(
            fg_color=COLORS["bg_panel"],
            border_width=1,
            border_color=COLORS["border"],
            corner_radius=8,
        )
        self.tool_name = tool_name
        self.status = status
        self.expanded = False

        # Header
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=12, pady=8)

        self.status_icon = ctk.CTkLabel(
            self.header_frame,
            text="◌" if status == "running" else "✓" if status == "success" else "✕",
            font=("Segoe UI", 14),
            text_color=COLORS["success"] if status == "success" else COLORS["critical"] if status == "failed" else COLORS["accent"],
        )
        self.status_icon.pack(side="left")

        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text=tool_name,
            font=("Segoe UI", 12, "bold"),
            text_color=COLORS["text_primary"],
        )
        self.title_label.pack(side="left", padx=8)

        self.duration_label = ctk.CTkLabel(
            self.header_frame,
            text="",
            font=("Segoe UI", 10),
            text_color=COLORS["text_secondary"],
        )
        self.duration_label.pack(side="right")

        # Expand button
        self.expand_btn = ctk.CTkButton(
            self.header_frame,
            text="▼",
            width=24,
            height=24,
            font=("Segoe UI", 10),
            fg_color="transparent",
            text_color=COLORS["text_secondary"],
            hover_color=COLORS["bg_secondary"],
            command=self._toggle_expand,
        )
        self.expand_btn.pack(side="right", padx=8)

        # Details frame (hidden by default)
        self.details_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_secondary"])
        self.details_frame.pack(fill="x", padx=12, pady=(0, 12))
        self.details_frame.pack_forget()

        self.details_text = ctk.CTkTextbox(
            self.details_frame,
            font=("Consolas", 10),
            fg_color=COLORS["bg_secondary"],
            text_color=COLORS["text_secondary"],
            border_width=0,
            height=80,
        )
        self.details_text.pack(fill="both", expand=True, padx=8, pady=8)

    def _toggle_expand(self):
        self.expanded = not self.expanded
        if self.expanded:
            self.details_frame.pack(fill="x", padx=12, pady=(0, 12))
            self.expand_btn.configure(text="▲")
        else:
            self.details_frame.pack_forget()
            self.expand_btn.configure(text="▼")

    def set_status(self, status: str, duration: str = ""):
        self.status = status
        icon = "✓" if status == "success" else "✕" if status == "failed" else "◌"
        color = COLORS["success"] if status == "success" else COLORS["critical"] if status == "failed" else COLORS["accent"]
        self.status_icon.configure(text=icon, text_color=color)
        if duration:
            self.duration_label.configure(text=duration)

    def add_detail(self, text: str):
        self.details_text.insert("end", text + "\n")
        self.details_text.see("end")


class FindingCard(ctk.CTkFrame):
    """Interactive finding card."""

    def __init__(self, master, finding: Dict, on_click: Callable = None, **kwargs):
        super().__init__(master, **kwargs)
        self.finding = finding
        self.on_click = on_click
        self.configure(
            fg_color=COLORS["bg_panel"],
            border_width=1,
            border_color=SEVERITY_COLORS.get(finding.get("severity", "INFO"), COLORS["border"]),
            corner_radius=8,
        )

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=12, pady=10)

        # Severity badge
        severity = finding.get("severity", "INFO")
        severity_color = SEVERITY_COLORS.get(severity, COLORS["text_secondary"])
        severity_badge = ctk.CTkLabel(
            content,
            text=severity,
            font=("Segoe UI", 10, "bold"),
            text_color=severity_color,
            fg_color=COLORS["bg_secondary"],
            corner_radius=4,
            padx=6,
            pady=2,
        )
        severity_badge.pack(anchor="w", pady=(0, 4))

        # Title
        title = finding.get("title", finding.get("detection_reason", "Unknown Finding"))
        ctk.CTkLabel(
            content,
            text=title,
            font=("Segoe UI", 12, "bold"),
            text_color=COLORS["text_primary"],
            anchor="w",
        ).pack(fill="x", pady=(0, 4))

        # Location/Context
        location = finding.get("location", finding.get("related_entities", {}).get("files", [""])[0])
        if location:
            ctk.CTkLabel(
                content,
                text=location,
                font=("Segoe UI", 10),
                text_color=COLORS["text_secondary"],
                anchor="w",
            ).pack(fill="x", pady=(0, 4))

        # MITRE technique
        mitre = finding.get("mitre_technique", "")
        if mitre:
            ctk.CTkLabel(
                content,
                text=f"MITRE: {mitre}",
                font=("Segoe UI", 10),
                text_color=COLORS["accent"],
                anchor="w",
            ).pack(fill="x")

        if self.on_click:
            self.bind("<Button-1>", lambda e: self.on_click(finding))
            content.bind("<Button-1>", lambda e: self.on_click(finding))


class MessageBubble(ctk.CTkFrame):
    """Chat message bubble."""

    def __init__(self, master, role: str, content: str, **kwargs):
        super().__init__(master, **kwargs)
        self.role = role
        self.content = content

        is_user = role == "user"
        self.configure(
            fg_color=COLORS["bg_panel"] if not is_user else COLORS["accent"],
            border_width=0,
            corner_radius=12,
        )

        # Role label
        role_label = ctk.CTkLabel(
            self,
            text="You" if is_user else "Cyber Agent",
            font=("Segoe UI", 10, "bold"),
            text_color=COLORS["accent"] if is_user else COLORS["text_secondary"],
            anchor="w",
        )
        role_label.pack(anchor="w", padx=16, pady=(12, 4))

        # Content
        content_label = ctk.CTkLabel(
            self,
            text=content,
            font=("Segoe UI", 12),
            text_color=COLORS["text_primary"] if not is_user else "#FFFFFF",
            anchor="w",
            wraplength=600,
            justify="left",
        )
        content_label.pack(anchor="w", padx=16, pady=(0, 12))


class AgentWorkspace(ctk.CTk):
    """Main agent workspace application."""

    def __init__(self):
        super().__init__()

        self.title("CyberAgent - Autonomous Security Workspace")
        self.geometry("1400x850")
        self.minsize(1200, 700)

        # State
        self.session_manager = SessionManager()
        self.current_session: Optional[Session] = None
        self.event_bus: Optional[AgentEventBus] = None
        self.sidebar_visible = True
        self.context_visible = True
        self.command_palette_visible = False
        self.active_tools: Dict[str, ToolExecutionCard] = {}
        self.agent_state = "IDLE"
        self.activity_log: List[Dict] = []
        # ToolOrchestrator delegates execution to a CyberAgent. Without one, every
        # tool call fails with "NAT tool execution requires a CyberAgent executor",
        # so the agent appears to answer while silently running no tools at all.
        # Imported lazily: cyber_agent imports cyber_os, so a module-level import
        # here would be a circular import.
        try:
            from cyber_agent import CyberAgent
            self.agent = CyberAgent(workspace_path=".")
        except ImportError as exc:
            self.agent = None
            print(f"[!] AgentWorkspace: CyberAgent unavailable, tools cannot execute: {exc}")
        self.orchestrator = ToolOrchestrator(workspace_path=".", use_mock_llm=False, agent=self.agent)
        self.current_findings: List[Dict] = []

        # Build UI
        self._build_header()
        self._build_sidebar()
        self._build_main_content()
        self._build_context_panel()
        self._build_footer()
        self._bind_shortcuts()

        # Create initial session
        self._new_session("New Investigation")

        # Start event processing
        self._process_event_queue()

    def _build_header(self):
        """Build the top header bar."""
        self.header = ctk.CTkFrame(self, height=48, fg_color=COLORS["bg_secondary"], border_width=0)
        self.header.pack(side="top", fill="x")
        self.header.pack_propagate(False)

        # Logo
        logo_frame = ctk.CTkFrame(self.header, fg_color="transparent")
        logo_frame.pack(side="left", padx=16, pady=8)

        ctk.CTkLabel(
            logo_frame,
            text="CyberAgent",
            font=("Segoe UI", 14, "bold"),
            text_color=COLORS["text_primary"],
        ).pack(side="left")

        ctk.CTkLabel(
            logo_frame,
            text="Autonomous Security Workspace",
            font=("Segoe UI", 10),
            text_color=COLORS["text_secondary"],
        ).pack(side="left", padx=(8, 0))

        # Session title
        self.session_title = ctk.CTkLabel(
            self.header,
            text="New Investigation",
            font=("Segoe UI", 11),
            text_color=COLORS["text_secondary"],
        )
        self.session_title.pack(side="left", padx=24)

        # Status indicators
        status_frame = ctk.CTkFrame(self.header, fg_color="transparent")
        status_frame.pack(side="right", padx=16, pady=8)

        self.agent_status_label = ctk.CTkLabel(
            status_frame,
            text="● Agent Ready",
            font=("Segoe UI", 11),
            text_color=COLORS["success"],
        )
        self.agent_status_label.pack(side="right", padx=12)

        self.wsl_status_label = ctk.CTkLabel(
            status_frame,
            text="WSL ●",
            font=("Segoe UI", 11),
            text_color=COLORS["text_secondary"],
        )
        self.wsl_status_label.pack(side="right", padx=12)

        self.ai_status_label = ctk.CTkLabel(
            status_frame,
            text="AI ●",
            font=("Segoe UI", 11),
            text_color=COLORS["text_secondary"],
        )
        self.ai_status_label.pack(side="right", padx=12)

    def _build_sidebar(self):
        """Build the left workspace sidebar."""
        self.sidebar = ctk.CTkFrame(self, width=260, fg_color=COLORS["bg_secondary"], border_width=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # New session button
        self.new_session_btn = ctk.CTkButton(
            self.sidebar,
            text="+ New Investigation",
            font=("Segoe UI", 11, "bold"),
            fg_color=COLORS["accent"],
            hover_color="#1F6FEB",
            command=self._new_session_prompt,
        )
        self.new_session_btn.pack(fill="x", padx=12, pady=12)

        # Search
        self.search_entry = ctk.CTkEntry(
            self.sidebar,
            placeholder_text="Search...",
            font=("Segoe UI", 11),
            fg_color=COLORS["bg_panel"],
            border_width=1,
            border_color=COLORS["border"],
        )
        self.search_entry.pack(fill="x", padx=12, pady=(0, 12))

        # Sessions section
        ctk.CTkLabel(
            self.sidebar,
            text="RECENT",
            font=("Segoe UI", 10, "bold"),
            text_color=COLORS["text_secondary"],
        ).pack(anchor="w", padx=12, pady=(0, 4))

        self.sessions_frame = ctk.CTkScrollableFrame(self.sidebar, fg_color="transparent", height=200)
        self.sessions_frame.pack(fill="x", padx=12, pady=(0, 12))

        # Workspaces section
        ctk.CTkLabel(
            self.sidebar,
            text="WORKSPACES",
            font=("Segoe UI", 10, "bold"),
            text_color=COLORS["text_secondary"],
        ).pack(anchor="w", padx=12, pady=(0, 4))

        workspaces = [
            "Security Analysis",
            "Incident Response",
            "Threat Hunting",
            "Forensics",
            "Vulnerability Research",
        ]

        for workspace in workspaces:
            btn = ctk.CTkButton(
                self.sidebar,
                text=workspace,
                font=("Segoe UI", 11),
                fg_color="transparent",
                text_color=COLORS["text_primary"],
                hover_color=COLORS["bg_panel"],
                anchor="w",
                command=lambda w=workspace: self._load_workspace(w),
            )
            btn.pack(fill="x", padx=12, pady=1)

        # Bottom utilities
        utils_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        utils_frame.pack(side="bottom", fill="x", padx=12, pady=12)

        ctk.CTkButton(
            utils_frame,
            text="⚙ Settings",
            font=("Segoe UI", 11),
            fg_color="transparent",
            text_color=COLORS["text_secondary"],
            hover_color=COLORS["bg_panel"],
            anchor="w",
        ).pack(fill="x", pady=1)

        ctk.CTkButton(
            utils_frame,
            text="? Help",
            font=("Segoe UI", 11),
            fg_color="transparent",
            text_color=COLORS["text_secondary"],
            hover_color=COLORS["bg_panel"],
            anchor="w",
        ).pack(fill="x", pady=1)

    def _build_main_content(self):
        """Build the central agent conversation area."""
        self.main_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_primary"], border_width=0)
        self.main_frame.pack(side="left", fill="both", expand=True)

        # Conversation area
        self.conversation_frame = ctk.CTkScrollableFrame(
            self.main_frame,
            fg_color=COLORS["bg_primary"],
            border_width=0,
        )
        self.conversation_frame.pack(side="top", fill="both", expand=True, padx=24, pady=24)

        # Input area
        input_frame = ctk.CTkFrame(self.main_frame, fg_color=COLORS["bg_secondary"], height=120, border_width=0)
        input_frame.pack(side="bottom", fill="x", padx=24, pady=24)
        input_frame.pack_propagate(False)

        # Command palette hint
        palette_hint = ctk.CTkLabel(
            input_frame,
            text="Ctrl+K for commands",
            font=("Segoe UI", 9),
            text_color=COLORS["text_secondary"],
        )
        palette_hint.pack(anchor="w", padx=12, pady=(8, 0))

        self.chat_input = ctk.CTkTextbox(
            input_frame,
            font=("Segoe UI", 12),
            fg_color=COLORS["bg_panel"],
            border_width=1,
            border_color=COLORS["border"],
            corner_radius=8,
            height=60,
        )
        self.chat_input.pack(fill="x", padx=12, pady=8)
        self.chat_input.bind("<Return>", lambda e: self._send_message())
        self.chat_input.bind("<Shift-Return>", lambda e: None)

        # Send button
        self.send_btn = ctk.CTkButton(
            input_frame,
            text="Send ↑",
            font=("Segoe UI", 11, "bold"),
            fg_color=COLORS["accent"],
            hover_color="#1F6FEB",
            width=80,
            command=self._send_message,
        )
        self.send_btn.pack(side="right", padx=12, pady=(0, 12))

    def _build_context_panel(self):
        """Build the right context panel."""
        self.context_panel = ctk.CTkFrame(self, width=300, fg_color=COLORS["bg_secondary"], border_width=0)
        self.context_panel.pack(side="right", fill="y")
        self.context_panel.pack_propagate(False)

        # Context tabs
        self.context_tabs = ctk.CTkSegmentedButton(
            self.context_panel,
            values=["Findings", "Files", "MITRE", "Activity"],
            font=("Segoe UI", 11),
            selected_color=COLORS["accent"],
            unselected_color=COLORS["bg_panel"],
            text_color=COLORS["text_primary"],
        )
        self.context_tabs.pack(fill="x", padx=12, pady=12)
        self.context_tabs.set("Findings")

        # Context content
        self.context_content = ctk.CTkScrollableFrame(
            self.context_panel,
            fg_color="transparent",
        )
        self.context_content.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        # Show empty state
        self._show_context_empty()

    def _show_context_empty(self):
        """Show empty state in context panel."""
        for widget in self.context_content.winfo_children():
            widget.destroy()

        ctk.CTkLabel(
            self.context_content,
            text="No active investigation",
            font=("Segoe UI", 12),
            text_color=COLORS["text_secondary"],
        ).pack(pady=20)

    def _build_footer(self):
        """Build the bottom status bar."""
        self.footer = ctk.CTkFrame(self, height=32, fg_color=COLORS["bg_secondary"], border_width=0)
        self.footer.pack(side="bottom", fill="x")
        self.footer.pack_propagate(False)

        self.status_label = ctk.CTkLabel(
            self.footer,
            text="● Agent Ready",
            font=("Segoe UI", 10),
            text_color=COLORS["success"],
        )
        self.status_label.pack(side="left", padx=16, pady=4)

        self.event_count_label = ctk.CTkLabel(
            self.footer,
            text="",
            font=("Segoe UI", 10),
            text_color=COLORS["text_secondary"],
        )
        self.event_count_label.pack(side="right", padx=16, pady=4)

    def _bind_shortcuts(self):
        """Bind keyboard shortcuts."""
        self.bind("<Control-k>", lambda e: self._toggle_command_palette())
        self.bind("<Control-b>", lambda e: self._toggle_sidebar())
        self.bind("<Control-Shift-b>", lambda e: self._toggle_context())

    def _toggle_command_palette(self):
        """Toggle command palette."""
        if self.command_palette_visible:
            self._hide_command_palette()
        else:
            self._show_command_palette()

    def _show_command_palette(self):
        """Show the command palette."""
        if hasattr(self, '_palette_window') and self._palette_window:
            self._palette_window.destroy()

        self._palette_window = ctk.CTkToplevel(self)
        self._palette_window.title("Command Palette")
        self._palette_window.geometry("600x400")
        self._palette_window.configure(fg_color=COLORS["bg_secondary"])

        # Search
        self.palette_search = ctk.CTkEntry(
            self._palette_window,
            placeholder_text="Search commands...",
            font=("Segoe UI", 12),
            fg_color=COLORS["bg_panel"],
            border_width=1,
            border_color=COLORS["border"],
        )
        self.palette_search.pack(fill="x", padx=16, pady=16)

        # Commands list
        commands = [
            ("Analyze File", "Analyze a file for security issues"),
            ("Scan Workspace", "Scan entire workspace for threats"),
            ("Scan for Secrets", "Find hardcoded credentials"),
            ("Threat Triage", "Run AI-powered threat triage"),
            ("Generate Incident Report", "Create incident report"),
            ("MITRE ATT&CK Mapping", "Map findings to MITRE techniques"),
            ("Start Investigation", "Begin new investigation"),
            ("Threat Hunt", "Start threat hunting workflow"),
            ("Forensic Analysis", "Begin forensic investigation"),
            ("Run Full AI Workflow", "Execute complete AI workflow"),
            ("Start CyberOS", "Start autonomous monitoring"),
            ("Stop CyberOS", "Stop autonomous monitoring"),
            ("View Findings", "Show all findings"),
            ("Settings", "Open settings"),
        ]

        self.commands_frame = ctk.CTkScrollableFrame(self._palette_window, fg_color="transparent")
        self.commands_frame.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        for cmd, desc in commands:
            cmd_btn = ctk.CTkButton(
                self.commands_frame,
                text=f"  {cmd}",
                font=("Segoe UI", 11),
                fg_color="transparent",
                text_color=COLORS["text_primary"],
                hover_color=COLORS["bg_panel"],
                anchor="w",
                command=lambda c=cmd: self._execute_command(c),
            )
            cmd_btn.pack(fill="x", pady=1)

        self.palette_search.focus_set()
        self.command_palette_visible = True

    def _hide_command_palette(self):
        """Hide the command palette."""
        if hasattr(self, '_palette_window') and self._palette_window:
            self._palette_window.destroy()
            self._palette_window = None
        self.command_palette_visible = False

    def _execute_command(self, command: str):
        """Execute a command from the palette."""
        self._hide_command_palette()
        self.chat_input.delete("1.0", "end")
        self.chat_input.insert("1.0", f"/{command.lower().replace(' ', '_')}")
        self._send_message()

    def _toggle_sidebar(self):
        """Toggle left sidebar."""
        if self.sidebar_visible:
            self.sidebar.pack_forget()
        else:
            self.sidebar.pack(side="left", fill="y")
        self.sidebar_visible = not self.sidebar_visible

    def _toggle_context(self):
        """Toggle right context panel."""
        if self.context_visible:
            self.context_panel.pack_forget()
        else:
            self.context_panel.pack(side="right", fill="y")
        self.context_visible = not self.context_visible

    def _new_session(self, title: str = "New Investigation"):
        """Create a new investigation session."""
        self.current_session = self.session_manager.create_session(title)
        self.session_title.configure(text=title)
        self.event_bus = AgentEventBus(self.current_session.session_id)
        self.event_bus.start()

        # Clear conversation
        for widget in self.conversation_frame.winfo_children():
            widget.destroy()

        # Add welcome message
        self._add_agent_message(
            "Your autonomous security workspace.\n\n"
            "Analyze code, investigate incidents, hunt threats, and understand risk.\n\n"
            "Try asking me to investigate your workspace, analyze a file, or run a security scan."
        )

        # Refresh session list
        self._refresh_sessions()

    def _new_session_prompt(self):
        """Prompt for new session name."""
        dialog = ctk.CTkInputDialog(
            text="Enter investigation name:",
            title="New Investigation",
        )
        name = dialog.get_input()
        if name:
            self._new_session(name)

    def _load_workspace(self, workspace: str):
        """Load a workspace preset."""
        prompts = {
            "Security Analysis": "Analyze the current workspace for security vulnerabilities and provide a risk assessment.",
            "Incident Response": "Investigate any suspicious activity in the system and build an incident response plan.",
            "Threat Hunting": "Hunt for threats in the current environment. Look for anomalies, suspicious processes, and network indicators.",
            "Forensics": "Perform a forensic analysis of the system. Collect evidence, build a timeline, and identify artifacts.",
            "Vulnerability Research": "Research and identify vulnerabilities in the current codebase and system configuration.",
        }
        prompt = prompts.get(workspace, f"Start {workspace} investigation.")
        self.chat_input.delete("1.0", "end")
        self.chat_input.insert("1.0", prompt)
        self._send_message()

    def _refresh_sessions(self):
        """Refresh the sessions list in sidebar."""
        for widget in self.sessions_frame.winfo_children():
            widget.destroy()

        sessions = self.session_manager.get_all_sessions()
        for session in sessions[:10]:
            is_active = self.current_session and session.session_id == self.current_session.session_id
            btn = ctk.CTkButton(
                self.sessions_frame,
                text=f"{'◉' if is_active else '○'} {session.title}",
                font=("Segoe UI", 11),
                fg_color="transparent",
                text_color=COLORS["accent"] if is_active else COLORS["text_primary"],
                hover_color=COLORS["bg_panel"],
                anchor="w",
                command=lambda s=session: self._switch_session(s.session_id),
            )
            btn.pack(fill="x", pady=1)

    def _switch_session(self, session_id: str):
        """Switch to a different session."""
        session = self.session_manager.get_session(session_id)
        if session:
            self.current_session = session
            self.session_title.configure(text=session.title)
            self.event_bus = AgentEventBus(session.session_id)
            self.event_bus.start()

            # Reload conversation
            for widget in self.conversation_frame.winfo_children():
                widget.destroy()

            for msg in session.messages:
                self._add_message_bubble(msg["role"], msg["content"])

            self._refresh_sessions()

    def _send_message(self):
        """Send a message to the agent."""
        text = self.chat_input.get("1.0", "end").strip()
        if not text:
            return

        self.chat_input.delete("1.0", "end")

        # Handle slash commands
        if text.startswith("/"):
            self._handle_slash_command(text)
            return

        # Add user message bubble immediately
        self._add_message_bubble("user", text)
        if self.current_session:
            self.current_session.add_message("user", text)

        # Show thinking state
        self.agent_state = "PROCESSING"
        self._update_status("Processing...")

        def _process():
            try:
                result = self.orchestrator.handle_message(text)
                self._finalize_orchestration(result)
            except Exception as e:
                self._log_activity(f"Error: {e}")
                self._add_agent_message(f"Something went wrong: {e}")
                self.agent_state = "IDLE"
                self._update_status("Agent Ready")

        threading.Thread(target=_process, daemon=True).start()

    def _finalize_orchestration(self, result):
        """Render orchestrator result into the UI."""
        # Show tool execution cards
        for tool_call in result.tool_calls:
            status = tool_call.status
            card = self._add_tool_card(
                f"{tool_call.tool} ({tool_call.arguments})",
                "completed" if status == "completed" else "failed",
            )
            if tool_call.duration_ms:
                card.set_status(status, f"{tool_call.duration_ms / 1000:.1f}s")
            if tool_call.error:
                card.add_detail(f"ERROR: {tool_call.error}")
            elif tool_call.result:
                raw = tool_call.result.get("raw_output", "") or tool_call.result.get("output", "")
                if raw:
                    card.add_detail(raw[:800])

        # Update findings panel
        self.current_findings = result.findings
        self._update_findings_panel()

        # Add agent response
        self._add_agent_message(result.response)
        if self.current_session:
            self.current_session.add_message("agent", result.response)

        # Activity log
        self._log_activity(f"Response: {result.response[:120]}")
        if result.error:
            self._log_activity(f"Tool error: {result.error}")

        self.agent_state = "IDLE"
        self._update_status("Agent Ready")

    def _handle_slash_command(self, command: str):
        """Handle slash commands by passing through orchestrator."""
        self._add_message_bubble("user", command)
        if self.current_session:
            self.current_session.add_message("user", command)

        def _process():
            try:
                result = self.orchestrator.handle_message(command)
                self._finalize_orchestration(result)
            except Exception as e:
                self._add_agent_message(f"Command failed: {e}")
                self.agent_state = "IDLE"
                self._update_status("Agent Ready")

        threading.Thread(target=_process, daemon=True).start()

    def _update_findings_panel(self):
        """Update the right-panel Findings tab from real tool results."""
        for widget in self.context_content.winfo_children():
            widget.destroy()

        if not self.current_findings:
            self._show_context_empty()
            return

        for finding in self.current_findings:
            card = FindingCard(self.context_content, finding=finding)
            card.pack(fill="x", pady=6)

    def _run_tool_workflow(self, user_text: str, intent_result: IntentResult):
        """Legacy wrapper — now delegates to orchestrator."""
        result = self.orchestrator.handle_message(user_text)
        self._finalize_orchestration(result)

    def _run_demo_simulation(self, user_text: str):
        """Demo simulation is disabled — real tools execute instead."""
        result = self.orchestrator.handle_message(user_text)
        self._finalize_orchestration(result)

    def _generate_response(self, user_text: str, intent_result: IntentResult) -> str:
        """Generate response for non-tool intents via orchestrator."""
        result = self.orchestrator.handle_message(user_text)
        self._finalize_orchestration(result)
        return result.response

    def _generate_findings_response(self, intent: IntentType, user_text: str) -> str:
        """Legacy wrapper — delegates to orchestrator."""
        result = self.orchestrator.handle_message(user_text)
        return result.response

    def _update_context_panel_with_intent(self, intent: IntentType):
        """Legacy wrapper — now uses real findings."""
        self._update_findings_panel()

    def _log_activity(self, message: str):
        """Log activity to the activity panel and event bus."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "message": message,
            "state": self.agent_state,
        }
        self.activity_log.append(log_entry)

        if self.event_bus:
            event = AgentEvent(
                type=EventType.AGENT_MESSAGE,
                timestamp=datetime.now().isoformat(),
                session_id=self.event_bus.session_id,
                message=message,
                data={"state": self.agent_state},
            )
            self.event_bus.emit(event)

        self._update_activity_panel()

    def _update_activity_panel(self):
        """Update the activity panel with recent logs."""
        # This would update the right panel's Activity tab
        # For now, we update the footer event count
        self.event_count_label.configure(text=f"Events: {len(self.activity_log)}")

    def _update_status(self, status: str):
        """Update the status bar."""
        self.status_label.configure(text=f"● {status}")
        if self.event_bus:
            event = AgentEvent(
                type=EventType.STATUS_CHANGED,
                timestamp=datetime.now().isoformat(),
                session_id=self.event_bus.session_id,
                message=status,
            )
            self.event_bus.emit(event)

    def _add_message_bubble(self, role: str, content: str):
        """Add a message bubble to the conversation."""
        bubble = MessageBubble(
            self.conversation_frame,
            role=role,
            content=content,
            fg_color=COLORS["bg_panel"] if role != "user" else COLORS["accent"],
        )
        bubble.pack(fill="x", pady=8, anchor="w" if role != "user" else "e")

    def _add_agent_message(self, content: str):
        """Add an agent message to the conversation."""
        self._add_message_bubble("agent", content)
        if self.current_session:
            self.current_session.add_message("agent", content)

    def _add_tool_card(self, tool_name: str, status: str = "running"):
        """Add a tool execution card."""
        card = ToolExecutionCard(
            self.conversation_frame,
            tool_name=tool_name,
            status=status,
        )
        card.pack(fill="x", pady=4, anchor="w")
        self.active_tools[tool_name] = card
        return card

    def _process_event_queue(self):
        """Process events from the event bus (called periodically)."""
        if self.event_bus:
            events = self.event_bus.get_history(limit=10)
            if events:
                self.event_count_label.configure(text=f"Events: {len(self.event_bus.get_history(limit=1000))}")

        self.after(100, self._process_event_queue)

    def run(self):
        """Run the application."""
        self.mainloop()


def launch_workspace():
    """Launch the agent workspace."""
    try:
        app = AgentWorkspace()
        app.run()
    except Exception as e:
        print(f"Failed to launch workspace: {e}")
        raise


if __name__ == "__main__":
    launch_workspace()
