"""
CyberOS Dashboard
Live defense dashboard with real-time threat visualization.
"""

import os
import sys
import json
import time
import queue
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
from typing import Dict, Any, List, Optional

try:
    from cyber_os import CyberOSEngine, ThreatAlert, SecurityEvent, Severity
except ImportError:
    print("[!] cyber_os module not found. Run from project directory.")
    sys.exit(1)


class CyberOSDashboard:
    """Live defense dashboard for CyberOS."""

    def __init__(self, root, engine: CyberOSEngine):
        self.root = root
        self.engine = engine
        self.root.title("CyberOS - Autonomous Cyber Defense System")
        self.root.geometry("1400x900")
        self.root.configure(bg="#1e1e1e")
        
        self._setup_styles()
        self._build_ui()
        self._start_monitoring()
        self._poll_ui_queue()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background="#1e1e1e", foreground="#ffffff", font=("Consolas", 10))
        style.configure("TLabel", background="#1e1e1e", foreground="#ffffff")
        style.configure("TButton", background="#0e639c", foreground="#ffffff", font=("Consolas", 10, "bold"))
        style.map("TButton", background=[("active", "#1177bb")])
        style.configure("Status.TLabel", font=("Consolas", 10, "bold"))
        style.configure("Critical.TLabel", foreground="#ff4444", font=("Consolas", 11, "bold"))
        style.configure("High.TLabel", foreground="#ff8844", font=("Consolas", 10, "bold"))
        style.configure("Medium.TLabel", foreground="#ffcc00", font=("Consolas", 10))
        style.configure("Info.TLabel", foreground="#cccccc", font=("Consolas", 10))

    def _build_ui(self):
        # Top Header Bar
        header = tk.Frame(self.root, bg="#252526", height=60)
        header.pack(fill=tk.X, side=tk.TOP)
        
        # Title
        title_label = tk.Label(
            header,
            text="🛡️ CYBEROS - AUTONOMOUS CYBER DEFENSE SYSTEM",
            font=("Consolas", 16, "bold"),
            bg="#252526",
            fg="#00ff66"
        )
        title_label.pack(side=tk.LEFT, padx=20, pady=10)
        
        # Status Badges
        self.badge_frame = tk.Frame(header, bg="#252526")
        self.badge_frame.pack(side=tk.RIGHT, padx=15)
        
        self.status_badge = tk.Label(
            self.badge_frame, text="● MONITORING ACTIVE", 
            font=("Consolas", 11, "bold"), bg="#0e639c", fg="#ffffff"
        )
        self.status_badge.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.threat_badge = tk.Label(
            self.badge_frame, text="THREAT SCORE: 0/10", 
            font=("Consolas", 11, "bold"), bg="#333333", fg="#00ff66"
        )
        self.threat_badge.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.events_badge = tk.Label(
            self.badge_frame, text="EVENTS: 0", 
            font=("Consolas", 11, "bold"), bg="#333333", fg="#cccccc"
        )
        self.events_badge.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.alerts_badge = tk.Label(
            self.badge_frame, text="ALERTS: 0", 
            font=("Consolas", 11, "bold"), bg="#333333", fg="#ffcc00"
        )
        self.alerts_badge.pack(side=tk.LEFT, padx=5, pady=5)

        # Main Content Area
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg="#1e1e1e", bd=0)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left Panel - Controls & Stats
        left_panel = tk.Frame(main_pane, bg="#252526", width=350)
        main_pane.add(left_panel)
        
        # Control Section
        ctrl_frame = tk.LabelFrame(left_panel, text="🎮 CONTROL PANEL", bg="#252526", fg="#007acc", 
                                   font=("Consolas", 10, "bold"))
        ctrl_frame.pack(fill=tk.X, padx=10, pady=5, ipadx=5, ipady=5)
        
        self.btn_start = tk.Button(ctrl_frame, text="▶ START MONITORING", command=self._start_monitoring_btn,
                                   bg="#0e639c", fg="white", font=("Consolas", 10, "bold"), relief=tk.FLAT, padx=10, pady=5)
        self.btn_start.pack(fill=tk.X, padx=5, pady=2)
        
        self.btn_stop = tk.Button(ctrl_frame, text="⏹ STOP MONITORING", command=self._stop_monitoring_btn,
                                  bg="#a80000", fg="white", font=("Consolas", 10, "bold"), relief=tk.FLAT, padx=10, pady=5)
        self.btn_stop.pack(fill=tk.X, padx=5, pady=2)
        
        self.btn_reset = tk.Button(ctrl_frame, text="⟲ RESET SYSTEM", command=self._reset_system,
                                   bg="#cc7a00", fg="white", font=("Consolas", 10, "bold"), relief=tk.FLAT, padx=10, pady=5)
        self.btn_reset.pack(fill=tk.X, padx=5, pady=2)
        
        # Attack Simulation Section
        attack_frame = tk.LabelFrame(left_panel, text="⚔️ ATTACK SIMULATION", bg="#252526", fg="#ff4444",
                                     font=("Consolas", 10, "bold"))
        attack_frame.pack(fill=tk.X, padx=10, pady=5, ipadx=5, ipady=5)
        
        tk.Label(attack_frame, text="Launch controlled attacks to test CyberOS defense:", 
                bg="#252526", fg="#cccccc", font=("Consolas", 9)).pack(anchor=tk.W, padx=5, pady=2)
        
        self.btn_bruteforce = tk.Button(attack_frame, text="🔴 Brute Force Attack", 
                                        command=lambda: self._launch_attack("bruteforce"),
                                        bg="#8b0000", fg="white", font=("Consolas", 9, "bold"), 
                                        relief=tk.FLAT, padx=10, pady=3)
        self.btn_bruteforce.pack(fill=tk.X, padx=5, pady=2)
        
        self.btn_powershell = tk.Button(attack_frame, text="🟠 PowerShell Obfuscation", 
                                        command=lambda: self._launch_attack("powershell"),
                                        bg="#8b4513", fg="white", font=("Consolas", 9, "bold"), 
                                        relief=tk.FLAT, padx=10, pady=3)
        self.btn_powershell.pack(fill=tk.X, padx=5, pady=2)
        
        self.btn_portscan = tk.Button(attack_frame, text="🟡 Port Scan", 
                                      command=lambda: self._launch_attack("portscan"),
                                      bg="#8b7500", fg="white", font=("Consolas", 9, "bold"), 
                                      relief=tk.FLAT, padx=10, pady=3)
        self.btn_portscan.pack(fill=tk.X, padx=5, pady=2)
        
        self.btn_ransomware = tk.Button(attack_frame, text="🔴 Ransomware Simulation", 
                                        command=lambda: self._launch_attack("ransomware"),
                                        bg="#8b0000", fg="white", font=("Consolas", 9, "bold"), 
                                        relief=tk.FLAT, padx=10, pady=3)
        self.btn_ransomware.pack(fill=tk.X, padx=5, pady=2)
        
        # Stats Section
        stats_frame = tk.LabelFrame(left_panel, text="📊 SYSTEM STATS", bg="#252526", fg="#007acc",
                                    font=("Consolas", 10, "bold"))
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5, ipadx=5, ipady=5)
        
        self.stats_text = tk.Text(stats_frame, bg="#1e1e1e", fg="#00ff66", 
                                 font=("Consolas", 9), bd=0, height=15)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Center Panel - Event Feed
        center_panel = tk.Frame(main_pane, bg="#252526")
        main_pane.add(center_panel)
        
        event_title = tk.Label(center_panel, text="📡 LIVE EVENT FEED", 
                               font=("Consolas", 12, "bold"), bg="#252526", fg="#cccccc")
        event_title.pack(anchor=tk.W, padx=10, pady=10)
        
        self.event_feed = scrolledtext.ScrolledText(
            center_panel, bg="#1e1e1e", fg="#00ff66",
            insertbackground="white", font=("Consolas", 9), bd=0
        )
        self.event_feed.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.event_feed.tag_config("critical", foreground="#ff4444")
        self.event_feed.tag_config("high", foreground="#ff8844")
        self.event_feed.tag_config("medium", foreground="#ffcc00")
        self.event_feed.tag_config("info", foreground="#cccccc")
        self.event_feed.tag_config("success", foreground="#00ff66")
        self.event_feed.tag_config("ai", foreground="#61afef")
        
        # Right Panel - AI Reasoning
        right_panel = tk.Frame(main_pane, bg="#252526", width=400)
        main_pane.add(right_panel)
        
        ai_title = tk.Label(right_panel, text="🤖 AI REASONING", 
                            font=("Consolas", 12, "bold"), bg="#252526", fg="#cccccc")
        ai_title.pack(anchor=tk.W, padx=10, pady=10)
        
        self.ai_output = scrolledtext.ScrolledText(
            right_panel, bg="#1e1e1e", fg="#61afef",
            insertbackground="white", font=("Consolas", 9), bd=0
        )
        self.ai_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.ai_output.tag_config("ai", foreground="#61afef")
        self.ai_output.tag_config("reasoning", foreground="#98c379")
        self.ai_output.tag_config("action", foreground="#e5c07b")
        self.ai_output.tag_config("mitre", foreground="#c678dd")
        
        # Bottom Status Bar
        self.status_bar = tk.Frame(self.root, bg="#252526", height=30)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(self.status_bar, text="Ready", bg="#252526", fg="#cccccc", 
                                     font=("Consolas", 9))
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(self.status_bar, orient="horizontal", mode="indeterminate")

    def _start_monitoring(self):
        """Start the engine and update UI."""
        if not self.engine.running:
            self.engine.start()
            self.status_badge.config(text="● MONITORING ACTIVE", bg="#0e639c", fg="#ffffff")
            self.status_label.config(text="CyberOS monitoring active - All sensors online")
            self._log_event("SYSTEM", "CyberOS monitoring started", "success")

    def _start_monitoring_btn(self):
        self._start_monitoring()

    def _stop_monitoring_btn(self):
        """Stop monitoring."""
        self.engine.stop()
        self.status_badge.config(text="● STOPPED", bg="#a80000", fg="#ffffff")
        self.status_label.config(text="CyberOS monitoring stopped")
        self._log_event("SYSTEM", "CyberOS monitoring stopped", "warning")

    def _reset_system(self):
        """Reset all state."""
        self.engine.blocked_ips.clear()
        self.engine.blocked_ports.clear()
        self.engine.terminated_pids.clear()
        self.engine.quarantined_files.clear()
        self.engine.locked_accounts.clear()
        self.engine.threat_score = 0
        self.engine.events.clear()
        self.engine.alerts.clear()
        
        self.event_feed.delete("1.0", tk.END)
        self.ai_output.delete("1.0", tk.END)
        self._update_stats()
        self._log_event("SYSTEM", "System reset complete", "info")

    def _launch_attack(self, attack_type: str):
        """Launch a simulated attack."""
        self._log_event("ATTACK", f"Launching {attack_type} attack simulation...", "high")
        
        # Import attack scripts
        try:
            from cyber_os_attacks import launch_attack
            threading.Thread(
                target=launch_attack,
                args=(attack_type, self.engine),
                daemon=True
            ).start()
        except ImportError:
            self._log_event("ERROR", "cyber_os_attacks module not found", "critical")

    def _poll_ui_queue(self):
        """Poll the UI queue for new events."""
        try:
            while True:
                item = self.engine.ui_queue.get_nowait()
                if isinstance(item, ThreatAlert):
                    self._display_alert(item)
                elif isinstance(item, SecurityEvent):
                    self._display_event(item)
        except queue.Empty:
            pass
        
        # Update stats periodically
        self._update_stats()
        self.root.after(100, self._poll_ui_queue)

    def _display_event(self, event: SecurityEvent):
        """Display a security event in the feed."""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        severity_tag = event.severity.lower()
        
        msg = f"[{timestamp}] [{event.severity}] {event.event_type}: {event.details.get('event_id', 'N/A')}\n"
        self.event_feed.insert(tk.END, msg, severity_tag)
        self.event_feed.see(tk.END)

    def _display_alert(self, alert: ThreatAlert):
        """Display a threat alert in the feed and AI panel."""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        severity_tag = alert.severity.lower()
        
        # Event feed
        msg = f"[{timestamp}] [{alert.severity}] {alert.alert_type.upper()}: {alert.summary}\n"
        self.event_feed.insert(tk.END, msg, severity_tag)
        self.event_feed.see(tk.END)
        
        # AI Reasoning panel
        self.ai_output.insert(tk.END, f"\n{'='*60}\n", "ai")
        self.ai_output.insert(tk.END, f"🚨 THREAT DETECTED: {alert.technique_name}\n", "ai")
        self.ai_output.insert(tk.END, f"   MITRE: {alert.mitre_technique}\n", "mitre")
        self.ai_output.insert(tk.END, f"   Severity: {alert.severity}/10\n", "ai")
        self.ai_output.insert(tk.END, f"\n📋 Summary:\n", "reasoning")
        self.ai_output.insert(tk.END, f"   {alert.summary}\n", "reasoning")
        self.ai_output.insert(tk.END, f"\n🧠 AI Reasoning:\n", "reasoning")
        self.ai_output.insert(tk.END, f"   {alert.ai_reasoning}\n", "reasoning")
        self.ai_output.insert(tk.END, f"\n💥 Blast Radius:\n", "reasoning")
        self.ai_output.insert(tk.END, f"   {alert.blast_radius}\n", "reasoning")
        self.ai_output.insert(tk.END, f"\n✅ Recommended Actions:\n", "action")
        for action in alert.recommended_actions:
            self.ai_output.insert(tk.END, f"   • {action}\n", "action")
        
        if alert.autonomous_action_taken:
            self.ai_output.insert(tk.END, f"\n🤖 Autonomous Actions Taken:\n", "action")
            for action in alert.actions_taken:
                self.ai_output.insert(tk.END, f"   ✓ {action}\n", "success")
        
        self.ai_output.insert(tk.END, f"\n{'='*60}\n", "ai")
        self.ai_output.see(tk.END)

    def _log_event(self, source: str, message: str, severity: str = "info"):
        """Log an event to the event feed."""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        msg = f"[{timestamp}] [{source}] {message}\n"
        self.event_feed.insert(tk.END, msg, severity)
        self.event_feed.see(tk.END)

    def _update_stats(self):
        """Update statistics display."""
        status = self.engine.get_status()
        
        self.threat_badge.config(text=f"THREAT SCORE: {status['threat_score']}/10")
        
        # Color code threat score
        if status['threat_score'] >= 8:
            self.threat_badge.config(fg="#ff4444")
        elif status['threat_score'] >= 5:
            self.threat_badge.config(fg="#ffcc00")
        else:
            self.threat_badge.config(fg="#00ff66")
        
        self.events_badge.config(text=f"EVENTS: {status['total_events']}")
        self.alerts_badge.config(text=f"ALERTS: {status['total_alerts']}")
        
        # Update stats text
        stats_text = f"""CyberOS Status
═══════════════════════════════════════
Monitoring: {'ACTIVE' if status['running'] else 'STOPPED'}
Threat Score: {status['threat_score']}/10
Total Events: {status['total_events']}
Total Alerts: {status['total_alerts']}
Blocked IPs: {len(status['blocked_ips'])}
Blocked Ports: {len(status['blocked_ports'])}
Terminated PIDs: {len(status['terminated_pids'])}
Quarantined Files: {status['quarantined_files']}
═══════════════════════════════════════
"""
        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert(tk.END, stats_text)

    def on_close(self):
        """Handle window close."""
        self.engine.stop()
        self.root.destroy()


def run_dashboard():
    """Run the CyberOS dashboard."""
    root = tk.Tk()
    engine = CyberOSEngine()
    dashboard = CyberOSDashboard(root, engine)
    root.protocol("WM_DELETE_WINDOW", dashboard.on_close)
    root.mainloop()


if __name__ == "__main__":
    run_dashboard()
