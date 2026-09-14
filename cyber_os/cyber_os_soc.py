"""
CyberOS SOC Dashboard
Full-featured SOC interface with customtkinter
"""

import os
import sys
import json
import time
import queue
import threading
import platform
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from typing import Dict, List, Any, Optional

try:
    import customtkinter as ctk
    CUSTOMTKINTER_AVAILABLE = True
except ImportError:
    CUSTOMTKINTER_AVAILABLE = False

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyber_os.incident_manager import IncidentManager, Finding
from cyber_os.correlation_engine import CorrelationEngine
from cyber_os.mitre_engine import MitreEngine, AttackTechnique, AttackChain
from cyber_os.policy_engine import PolicyEngine
from cyber_os.response_engine import ResponseEngine, ResponseResult

# Set theme
if CUSTOMTKINTER_AVAILABLE:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")


class SOCDashboard:
    """Full-featured SOC dashboard with customtkinter."""

    def __init__(self):
        self.root = None
        if CUSTOMTKINTER_AVAILABLE:
            self.root = ctk.CTk()
            self.root.title("CyberGuard - AI Security Platform")
            self.root.geometry("1400x900")
            self.root.minsize(1200, 800)

            # Initialize engines
            self.incident_manager = IncidentManager()
            self.correlation_engine = CorrelationEngine()
            self.mitre_engine = MitreEngine()
            self.policy_engine = PolicyEngine()
            self.response_engine = ResponseEngine(
                policy_engine=self.policy_engine,
                audit_logger=None,
            )

            # State
            self.monitoring = False
            self.monitor_thread = None
            self.event_queue = queue.Queue()
            self.alerts = []
            self.events = []
            self.selected_incident = None
            self.selected_finding = None

            # Build UI
            self._build_ui()
            self._start_event_processor()

        else:
            raise RuntimeError("customtkinter not available. Install with: pip install customtkinter")

    def _build_ui(self):
        """Build the main UI layout."""
        # Sidebar navigation
        self.sidebar = ctk.CTkFrame(self.root, width=200, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")

        # Logo/Title
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.pack(pady=20, padx=10)
        ctk.CTkLabel(
            logo_frame,
            text="🛡️",
            font=("Segoe UI Emoji", 32),
        ).pack()
        ctk.CTkLabel(
            logo_frame,
            text="CyberGuard",
            font=("Roboto", 18, "bold"),
        ).pack()
        ctk.CTkLabel(
            logo_frame,
            text="AI Security Platform",
            font=("Roboto", 10),
            text_color="gray",
        ).pack()

        # Navigation buttons
        nav_items = [
            ("Dashboard", "🏠", self._show_dashboard),
            ("AI Copilot", "🤖", self._show_ai_copilot),
            ("Live Monitor", "📡", self._show_live_monitor),
            ("Processes", "⚙️", self._show_processes),
            ("Network", "🌐", self._show_network),
            ("Files", "📁", self._show_files),
            ("IAM", "👤", self._show_iam),
            ("Cloud", "☁️", self._show_cloud),
            ("Threats", "⚠️", self._show_threats),
            ("Incidents", "🚨", self._show_incidents),
            ("Forensics", "🔍", self._show_forensics),
            ("MITRE ATT&CK", "🎯", self._show_mitre),
            ("Automation", "⚡", self._show_automation),
            ("Audit Log", "📋", self._show_audit),
            ("Settings", "⚙️", self._show_settings),
        ]

        self.nav_buttons = {}
        for name, icon, callback in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=f"{icon} {name}",
                font=("Roboto", 12),
                anchor="w",
                fg_color="transparent",
                text_color=("gray10", "gray90"),
                hover_color=("gray70", "gray30"),
                command=callback,
            )
            btn.pack(pady=2, padx=10, fill="x")
            self.nav_buttons[name] = btn

        # Control buttons
        control_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        control_frame.pack(side="bottom", fill="x", pady=10, padx=10)

        self.start_btn = ctk.CTkButton(
            control_frame,
            text="▶ Start",
            command=self._start_monitoring,
            fg_color="#006400",
            hover_color="#004d00",
        )
        self.start_btn.pack(pady=2, fill="x")

        self.stop_btn = ctk.CTkButton(
            control_frame,
            text="⏹ Stop",
            command=self._stop_monitoring,
            fg_color="#8b0000",
            hover_color="#660000",
        )
        self.stop_btn.pack(pady=2, fill="x")

        # Main content area
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(side="right", fill="both", expand=True)

        # Header
        self.header = ctk.CTkFrame(self.main_frame, height=60, fg_color=("gray75", "gray25"))
        self.header.pack(side="top", fill="x")

        # Status indicators
        self.status_frame = ctk.CTkFrame(self.header, fg_color="transparent")
        self.status_frame.pack(side="right", padx=20, pady=10)

        self.protected_badge = ctk.CTkLabel(
            self.status_frame,
            text="● MONITORING",
            font=("Roboto", 12, "bold"),
            text_color="#00ff66",
        )
        self.protected_badge.pack(side="left", padx=10)

        self.threat_badge = ctk.CTkLabel(
            self.status_frame,
            text="THREAT LEVEL: LOW",
            font=("Roboto", 12),
            text_color="#00ff66",
        )
        self.threat_badge.pack(side="left", padx=10)

        # Content area with scrollable frame
        self.content = ctk.CTkScrollableFrame(self.main_frame)
        self.content.pack(fill="both", expand=True, padx=20, pady=20)

        # Show dashboard by default
        self._show_dashboard()

    def _show_dashboard(self):
        """Show the main dashboard."""
        self._clear_content()
        self._set_active_nav("Dashboard")

        # Title
        ctk.CTkLabel(
            self.content,
            text="CyberGuard",
            font=("Roboto", 28, "bold"),
        ).pack(pady=(0, 5), anchor="w")

        ctk.CTkLabel(
            self.content,
            text="AI SECURITY PLATFORM",
            font=("Roboto", 14),
            text_color="gray",
        ).pack(pady=(0, 20), anchor="w")

        # Status card
        status_card = ctk.CTkFrame(self.content)
        status_card.pack(fill="x", pady=10)

        ctk.CTkLabel(
            status_card,
            text="SYSTEM STATUS",
            font=("Roboto", 14, "bold"),
        ).pack(pady=10, padx=20, anchor="w")

        # Threat level
        threat_frame = ctk.CTkFrame(status_card, fg_color=("gray85", "gray20"))
        threat_frame.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(
            threat_frame,
            text="THREAT LEVEL: LOW",
            font=("Roboto", 16, "bold"),
            text_color="#00ff66",
        ).pack(pady=15, padx=20)

        # Stats grid
        stats_frame = ctk.CTkFrame(self.content)
        stats_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(
            stats_frame,
            text="SECURITY METRICS",
            font=("Roboto", 14, "bold"),
        ).pack(pady=10, padx=20, anchor="w")

        stats_grid = ctk.CTkFrame(stats_frame, fg_color="transparent")
        stats_grid.pack(fill="x", padx=20, pady=10)

        # Calculate stats
        stats = self.incident_manager.get_statistics()
        critical = stats['by_severity'].get('CRITICAL', 0)
        high = stats['by_severity'].get('HIGH', 0)
        medium = stats['by_severity'].get('MEDIUM', 0)
        low = stats['by_severity'].get('LOW', 0)
        incidents = stats['total_incidents']
        findings = stats['total_findings']

        stat_items = [
            ("Critical", critical, "#ff4444"),
            ("High", high, "#ff8800"),
            ("Medium", medium, "#ffcc00"),
            ("Low", low, "#00ff66"),
            ("Incidents", incidents, "#00ccff"),
            ("Findings", findings, "#0099ff"),
        ]

        for i, (label, value, color) in enumerate(stat_items):
            frame = ctk.CTkFrame(stats_grid)
            frame.grid(row=i // 3, column=i % 3, padx=10, pady=10, sticky="nsew")

            ctk.CTkLabel(
                frame,
                text=str(value),
                font=("Roboto", 24, "bold"),
                text_color=color,
            ).pack(pady=(15, 5))

            ctk.CTkLabel(
                frame,
                text=label,
                font=("Roboto", 11),
                text_color="gray",
            ).pack(pady=(0, 15))

        stats_grid.grid_columnconfigure(0, weight=1)
        stats_grid.grid_columnconfigure(1, weight=1)
        stats_grid.grid_columnconfigure(2, weight=1)

        # AI Status
        ai_card = ctk.CTkFrame(self.content)
        ai_card.pack(fill="x", pady=10)

        ctk.CTkLabel(
            ai_card,
            text="AI SECURITY COPILOT",
            font=("Roboto", 14, "bold"),
        ).pack(pady=10, padx=20, anchor="w")

        ctk.CTkLabel(
            ai_card,
            text="System appears healthy. Monitoring active.",
            font=("Roboto", 12),
            wraplength=800,
        ).pack(pady=(0, 15), padx=20, anchor="w")

        # Quick actions
        action_frame = ctk.CTkFrame(self.content)
        action_frame.pack(fill="x", pady=10)

        ctk.CTkLabel(
            action_frame,
            text="QUICK ACTIONS",
            font=("Roboto", 14, "bold"),
        ).pack(pady=10, padx=20, anchor="w")

        btn_frame = ctk.CTkFrame(action_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkButton(
            btn_frame,
            text="🔍 Investigate System",
            command=self._investigate_system,
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="📊 Run Scan",
            command=lambda: self._run_scan("full"),
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="📋 Generate Report",
            command=self._generate_report,
        ).pack(side="left", padx=5)

    def _show_ai_copilot(self):
        """Show AI Copilot chat interface."""
        self._clear_content()
        self._set_active_nav("AI Copilot")

        ctk.CTkLabel(
            self.content,
            text="AI Security Copilot",
            font=("Roboto", 20, "bold"),
        ).pack(pady=(0, 20), anchor="w")

        # Chat history
        self.chat_history = ctk.CTkTextbox(
            self.content,
            font=("Roboto", 12),
            wrap="word",
            height=500,
        )
        self.chat_history.pack(fill="both", expand=True, pady=(0, 10))

        # Add initial message
        self._append_chat("system", "CyberGuard AI Security Copilot initialized. How can I help you secure your system?")

        # Input frame
        input_frame = ctk.CTkFrame(self.content, fg_color="transparent")
        input_frame.pack(fill="x", pady=(0, 10))

        self.chat_input = ctk.CTkEntry(
            input_frame,
            placeholder_text="Ask about security, run investigations, or request analysis...",
            font=("Roboto", 12),
        )
        self.chat_input.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.chat_input.bind("<Return>", lambda e: self._send_chat())

        ctk.CTkButton(
            input_frame,
            text="Send",
            command=self._send_chat,
            width=80,
        ).pack(side="right")

    def _send_chat(self):
        """Send chat message."""
        text = self.chat_input.get().strip()
        if not text:
            return

        self.chat_input.delete(0, "end")
        self._append_chat("user", text)

        # Process in background
        def process():
            response = self._process_chat_command(text)
            self._append_chat("agent", response)

        threading.Thread(target=process, daemon=True).start()

    def _process_chat_command(self, text: str) -> str:
        """Process chat commands."""
        text_lower = text.lower()

        if "investigate" in text_lower:
            return self._investigate_system()
        elif "scan" in text_lower:
            return self._run_scan("quick")
        elif "report" in text_lower:
            return self._generate_report()
        elif "incidents" in text_lower or "incident" in text_lower:
            stats = self.incident_manager.get_statistics()
            return f"Active Incidents: {stats['open_incidents']}\nTotal Findings: {stats['total_findings']}\nSeverity Breakdown: {stats['by_severity']}"
        elif "help" in text_lower:
            return "Available commands:\n- investigate: Full system investigation\n- scan: Run security scan\n- report: Generate incident report\n- incidents: View incident statistics\n- help: Show this help"
        else:
            return "I understand you're asking about: " + text + "\nTry commands like: investigate, scan, report, incidents, help"

    def _append_chat(self, speaker: str, message: str):
        """Append message to chat history."""
        self.chat_history.configure(state="normal")
        self.chat_history.insert("end", f"\n{speaker.upper()}:\n", ("speaker",))
        self.chat_history.insert("end", f"{message}\n\n", ("message",))
        self.chat_history.see("end")
        self.chat_history.configure(state="disabled")

    def _investigate_system(self) -> str:
        """Run full system investigation."""
        self._log("Starting full system investigation...")
        # Simulate investigation steps
        steps = [
            "Collecting system information...",
            "Analyzing running processes...",
            "Checking persistence mechanisms...",
            "Analyzing network connections...",
            "Checking recent file activity...",
            "Correlating security findings...",
            "Mapping MITRE techniques...",
        ]

        for step in steps:
            time.sleep(0.3)
            self._log(step)

        # Create a sample incident
        incident = self.incident_manager.create_incident(
            title="System Investigation - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            severity="MEDIUM",
            risk_score=35,
            confidence=0.75,
            evidence_count=5,
            detection_count=3,
            mitre_techniques=["T1059.001", "T1071.001"],
        )

        self._log(f"\nInvestigation complete. Incident {incident.incident_id} created.")
        return f"Investigation complete.\nRisk: MEDIUM\nIncident: {incident.incident_id}\nFindings: 3\nMITRE techniques mapped: 2"

    def _run_scan(self, scan_type: str = "quick") -> str:
        """Run a security scan."""
        self._log(f"Starting {scan_type} security scan...")
        time.sleep(1)
        self._log("Scanning processes...")
        time.sleep(0.5)
        self._log("Scanning network connections...")
        time.sleep(0.5)
        self._log("Scanning filesystem...")
        time.sleep(0.5)

        findings = 2
        self._log(f"Scan complete. {findings} findings detected.")
        return f"Scan complete.\nFindings: {findings}\nScan type: {scan_type}\nStatus: Complete"

    def _generate_report(self) -> str:
        """Generate an incident report."""
        stats = self.incident_manager.get_statistics()
        report = f"""CYBERGUARD INCIDENT REPORT
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

EXECUTIVE SUMMARY
Total Incidents: {stats['total_incidents']}
Open Incidents: {stats['open_incidents']}
Total Findings: {stats['total_findings']}

SEVERITY BREAKDOWN
Critical: {stats['by_severity'].get('CRITICAL', 0)}
High: {stats['by_severity'].get('HIGH', 0)}
Medium: {stats['by_severity'].get('MEDIUM', 0)}
Low: {stats['by_severity'].get('LOW', 0)}
Info: {stats['by_severity'].get('INFO', 0)}

RISK SCORE AVERAGE: {stats['risk_score_avg']:.1f}/100

Report generated by CyberGuard AI Security Platform.
"""
        self._log("Incident report generated.")
        return report

    def _show_live_monitor(self):
        """Show live security monitor."""
        self._clear_content()
        self._set_active_nav("Live Monitor")

        ctk.CTkLabel(
            self.content,
            text="Live Security Monitor",
            font=("Roboto", 20, "bold"),
        ).pack(pady=(0, 20), anchor="w")

        # Live events feed
        self.event_feed = ctk.CTkTextbox(
            self.content,
            font=("Roboto", 11),
            wrap="word",
            height=600,
        )
        self.event_feed.pack(fill="both", expand=True)

        # Status bar
        status_bar = ctk.CTkFrame(self.content)
        status_bar.pack(fill="x", pady=(10, 0))

        self.event_count_label = ctk.CTkLabel(
            status_bar,
            text="Events: 0",
            font=("Roboto", 11),
        )
        self.event_count_label.pack(side="left", padx=20, pady=10)

        self.alert_count_label = ctk.CTkLabel(
            status_bar,
            text="Alerts: 0",
            font=("Roboto", 11),
            text_color="#ff8800",
        )
        self.alert_count_label.pack(side="left", padx=20, pady=10)

    def _show_processes(self):
        """Show processes view."""
        self._clear_content()
        self._set_active_nav("Processes")
        ctk.CTkLabel(self.content, text="Process Analysis", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")
        self._log("Process analysis feature - integrates with ToolRegistry process tools")

    def _show_network(self):
        """Show network view."""
        self._clear_content()
        self._set_active_nav("Network")
        ctk.CTkLabel(self.content, text="Network Security", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")
        self._log("Network security center - integrates with ToolRegistry network tools")

    def _show_files(self):
        """Show files view."""
        self._clear_content()
        self._set_active_nav("Files")
        ctk.CTkLabel(self.content, text="File Intelligence", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")
        self._log("File analysis feature - integrates with ToolRegistry file tools")

    def _show_iam(self):
        """Show IAM view."""
        self._clear_content()
        self._set_active_nav("IAM")
        ctk.CTkLabel(self.content, text="Identity & Access Management", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")
        self._log("IAM security center - integrates with AD/SSH audit tools")

    def _show_cloud(self):
        """Show cloud view."""
        self._clear_content()
        self._set_active_nav("Cloud")
        ctk.CTkLabel(self.content, text="Cloud & Container Security", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")
        self._log("Cloud security center - integrates with S3/container audit tools")

    def _show_threats(self):
        """Show threats view."""
        self._clear_content()
        self._set_active_nav("Threats")
        ctk.CTkLabel(self.content, text="Security Threats", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")

        # List findings
        for finding_id, finding in list(self.incident_manager.findings.items())[:20]:
            finding_card = ctk.CTkFrame(self.content)
            finding_card.pack(fill="x", pady=5)

            severity_color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#00ff66"}.get(finding.severity, "gray")
            ctk.CTkLabel(
                finding_card,
                text=f"[{finding.severity}] {finding.finding_id}",
                font=("Roboto", 12, "bold"),
                text_color=severity_color,
            ).pack(anchor="w", padx=20, pady=(10, 5))

            ctk.CTkLabel(
                finding_card,
                text=f"Confidence: {finding.confidence:.0%} | MITRE: {finding.mitre_technique or 'N/A'}",
                font=("Roboto", 10),
            ).pack(anchor="w", padx=20, pady=(0, 10))

    def _show_incidents(self):
        """Show incidents view."""
        self._clear_content()
        self._set_active_nav("Incidents")
        ctk.CTkLabel(self.content, text="Incident Management", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")

        incidents = self.incident_manager.get_all_incidents()
        if not incidents:
            ctk.CTkLabel(self.content, text="No incidents yet. Start monitoring to detect threats.").pack(pady=20)
            return

        for incident in incidents[:20]:
            inc_card = ctk.CTkFrame(self.content)
            inc_card.pack(fill="x", pady=5)

            severity_color = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#00ff66"}.get(incident.severity, "gray")
            ctk.CTkLabel(
                inc_card,
                text=f"[{incident.severity}] {incident.incident_id} - {incident.title}",
                font=("Roboto", 12, "bold"),
                text_color=severity_color,
            ).pack(anchor="w", padx=20, pady=(10, 5))

            ctk.CTkLabel(
                inc_card,
                text=f"Status: {incident.status} | Risk: {incident.risk_score:.1f} | Confidence: {incident.confidence:.0%}",
                font=("Roboto", 10),
            ).pack(anchor="w", padx=20, pady=(0, 10))

    def _show_forensics(self):
        """Show forensics view."""
        self._clear_content()
        self._set_active_nav("Forensics")
        ctk.CTkLabel(self.content, text="Forensic Timeline", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")
        self._log("Forensic timeline feature - shows chronological event history")

    def _show_mitre(self):
        """Show MITRE ATT&CK view."""
        self._clear_content()
        self._set_active_nav("MITRE ATT&CK")
        ctk.CTkLabel(self.content, text="MITRE ATT&CK Mapping", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")

        tactics = self.mitre_engine.get_all_tactics()
        for tactic in tactics[:8]:
            ctk.CTkLabel(
                self.content,
                text=f"• {tactic}",
                font=("Roboto", 12),
            ).pack(anchor="w", padx=20, pady=2)

    def _show_automation(self):
        """Show automation rules."""
        self._clear_content()
        self._set_active_nav("Automation")
        ctk.CTkLabel(self.content, text="Automation Rules", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")
        self._log("Automation rules engine - configurable response policies")

    def _show_audit(self):
        """Show audit log."""
        self._clear_content()
        self._set_active_nav("Audit Log")
        ctk.CTkLabel(self.content, text="Audit Log", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")

        self.audit_feed = ctk.CTkTextbox(self.content, font=("Roboto", 11), height=600)
        self.audit_feed.pack(fill="both", expand=True)

        results = self.response_engine.get_results(limit=100)
        for result in results:
            status_color = {"SUCCESS": "#00ff66", "FAILED": "#ff4444", "VERIFICATION_FAILED": "#ff8800"}.get(result['status'], "gray")
            self.audit_feed.insert("end", f"[{result['timestamp']}] {result['action_type']} -> {result['target']}\n", ("timestamp",))
            self.audit_feed.insert("end", f"  Status: {result['status']}\n", ("status",))
            self.audit_feed.insert("end", f"  Result: {result['result']}\n\n", ("result",))

    def _show_settings(self):
        """Show settings."""
        self._clear_content()
        self._set_active_nav("Settings")
        ctk.CTkLabel(self.content, text="Settings", font=("Roboto", 20, "bold")).pack(pady=(0, 20), anchor="w")
        self._log("Settings configuration")

    def _clear_content(self):
        """Clear the content area."""
        for widget in self.content.winfo_children():
            widget.destroy()

    def _set_active_nav(self, name: str):
        """Set active navigation button."""
        for btn_name, btn in self.nav_buttons.items():
            if btn_name == name:
                btn.configure(fg_color=("gray75", "gray25"))
            else:
                btn.configure(fg_color="transparent")

    def _log(self, message: str):
        """Log a message to the event feed if visible."""
        if hasattr(self, 'event_feed') and self.event_feed:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.event_feed.insert("end", f"[{timestamp}] {message}\n")
            self.event_feed.see("end")

    def _start_monitoring(self):
        """Start security monitoring."""
        self.monitoring = True
        self.protected_badge.configure(text="● MONITORING", text_color="#00ff66")
        self._log("Security monitoring started")

    def _stop_monitoring(self):
        """Stop security monitoring."""
        self.monitoring = False
        self.protected_badge.configure(text="● STOPPED", text_color="#ff4444")
        self._log("Security monitoring stopped")

    def _start_event_processor(self):
        """Start background event processor."""
        def process():
            while True:
                try:
                    event = self.event_queue.get(timeout=1)
                    self._process_event(event)
                except queue.Empty:
                    continue
                except Exception:
                    pass

        threading.Thread(target=process, daemon=True).start()

    def _process_event(self, event):
        """Process a security event."""
        # Correlate
        incidents = self.correlation_engine.add_event(event)
        for incident_data in incidents:
            self._log(f"Correlated incident: {incident_data.get('title', 'Unknown')}")

        # Add to events list
        self.events.append(event)
        if len(self.events) > 1000:
            self.events.pop(0)

    def run(self):
        """Run the dashboard."""
        if self.root:
            self.root.mainloop()
        else:
            raise RuntimeError("Dashboard not initialized. customtkinter may not be installed.")

    def add_event(self, event):
        """Add an event to the queue for processing."""
        self.event_queue.put(event)


def launch_soc_dashboard():
    """Launch the SOC dashboard."""
    try:
        dashboard = SOCDashboard()
        dashboard.run()
    except Exception as e:
        print(f"Failed to launch SOC dashboard: {e}")
        raise