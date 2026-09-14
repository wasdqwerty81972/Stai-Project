# CyberAI Security Suite — How It Works

## 1. Project Overview

This is a unified cybersecurity AI agent interface built in Python. It combines:
- 100+ security tools (scanners, analyzers, forensic utilities)
- SOC workflow management (incident response, threat hunting, forensic analysis)
- AI-enhanced threat analysis (via OmniRoute/Gemini API)
- Autonomous live defense (real-time monitoring + automated response)
- Multi-agent AI orchestration (13 specialized SOC agents)

---

## 2. Tech Stack & Requirements

- **Python 3.9+** (tested on 3.12)
- **CustomTkinter** — modern dark-themed GUI (primary UI)
- **Tkinter/ttk** — legacy dashboard UI
- **psutil** — system/process monitoring
- **pywin32** — Windows Event Log access
- **paramiko** — SSH honeypot server
- **requests** — HTTP calls (honeypot + LLM)
- **OpenAI SDK** — OmniRoute gateway client
- **google-genai** — Gemini fallback client
- **Pydantic Settings** — configuration management
- **JSON-first storage** — no mandatory PostgreSQL required

---

## 3. Directory Structure & Key Modules

### Top-level entry points
| File | Purpose |
|------|---------|
| `cyber_main.py` | **Primary GUI** — CustomTkinter 3-pane app with tabs (Agent, Files, Findings, MITRE, Dashboard, SOC, Tools, Workspace) |
| `cyber_ui.py` | **Legacy dashboard** — full tkinter UI with 19+ demo buttons for every capability |
| `cyber_agent.py` | **Core orchestrator** — wires together tools, AI, CyberDB, CyberOS; also defines 13 SOC agents + workflows |
| `cyber_tools.py` | **Tool registry & implementations** — 100+ tools, WSL routing, guardrails, static analysis, honeypot, etc. |
| `key_manager.py` | **AI API layer** — OmniRoute primary, Gemini fallback, mock/demo mode |
| `README.md` / `README_final.md` | Documentation |

### `cyber_os/` — Autonomous Live Defense System
| Module | Purpose |
|--------|---------|
| `engine.py` | Core engine: monitors Windows Event Logs, network, processes, filesystem, PowerShell. Detects brute force, port scans, ransomware, suspicious chains. Auto-responds by blocking IPs / killing PIDs. |
| `cyber_os_ai.py` | AI reasoning layer — analyzes alerts, generates incident reports, provides blast-radius assessments |
| `cyber_os_dashboard.py` | Live defense dashboard (tkinter) — event feed, AI reasoning panel, attack simulation buttons |
| `cyber_os_attacks.py` | Safe attack sims: bruteforce, PowerShell obfuscation, portscan, ransomware (uses `C:\AEGIS_Test`) |
| `incident_manager.py` | Incident & Finding models, correlation engine |
| `mitre_engine.py` | MITRE ATT&CK technique mapping, attack chain reconstruction |
| `policy_engine.py` | Security policies |
| `response_engine.py` | Autonomous response orchestration |
| `correlation_engine.py` | Multi-signal alert correlation |
| `cyber_os_soc.py` | SOC dashboard launcher |
| `agent_bus.py` | Event bus for agent-to-UI messaging |
| `intent_router.py` | NLP intent classification (conversational, analysis, investigation, incident response, etc.) |
| `workspace.py` | Agent workspace/session management |
| `tool_orchestrator.py` | Tool execution orchestration |
| `policies.json` / `cyber_os_config.json` | Configuration |

### `cyber_db/` — JSON-first Database Layer
| Module | Purpose |
|--------|---------|
| `__init__.py` | `CyberDB` class — CRUD for findings & cases in `data/findings.json` + `data/cases.json`; MITRE technique lookup; workflow/agent metadata |
| `schemas/` | Pydantic schemas for cases, findings, auth, AI, workflow, config |
| `data/` | JSON storage files |

### `cyber_soc_engine/` — SOC Engine Core
| Module | Purpose |
|--------|---------|
| `core/secrets.py` | Secrets getter/setter (encrypted store → env → dotenv → keyring) |
| `core/config.py` | Pydantic settings, state directory (`~/.vigil`), Redis defaults |
| `core/telemetry.py` | OpenTelemetry tracing |
| `core/auth/` | Password validation, reset, cookies, token blacklist |
| `core/llm/` | LLM gateway retry, chat layers, defaults |
| `core/threat_intel/` | Threat feed service, MITRE lookup, attack router |
| `core/agents/` | Tool registry, tools router, agent queue, prompts |
| `scripts/` | Setup, migration, data generation, Splunk export, demo scripts |

### `vigil_tools/` — SOC Workflow Tools
| Module | Purpose |
|--------|---------|
| `workflow_compiler.py` | Markdown workflow compiler + validator |
| `create_workflow.py` | Workflow template builder |
| `init_schema.py` | DB schema initialization |
| `seed_reference_data.py` | MITRE/agent reference data seeding |
| `finding_enricher.py` | Auto-enrich findings with MITRE mappings |
| `sample_data_generator.py` | Generate sample SOC data |

### `ui/` — UI Utilities
| Module | Purpose |
|--------|---------|
| `theme.py` | CustomTkinter dark theme colors/fonts |
| `event_bus.py` | Thread-safe publish/subscribe event system for agent ↔ UI communication |

---

## 4. How Everything Works (Data & Control Flow)

### A. Startup
1. **`cyber_main.py`** is the main entry point (`python cyber_main.py`)
2. It creates a `CyberMain` CustomTkinter window (1600x900, dark theme)
3. Initializes:
   - `ToolRegistry` + registers 100+ tools from `cyber_tools.py`
   - `WSLDetector` — checks if WSL is available for Linux tools
   - 3-pane layout: **sidebar** (sessions/workspaces), **main content** (tabs), **context panel**

### B. Tool Registry & Execution (`cyber_tools.py`)
- **`ToolRegistry`** holds all tools. Each `ToolDefinition` has:
  - `name`, `environments` (`cross_platform`, `native_windows`, `wsl_linux`)
  - `command_template` (for shell tools) or `python_func` (for Python tools)
  - `risk_level` (`READ_ONLY`, `MODIFIES_SYSTEM`, `DESTRUCTIVE`)
  - `fallback_tool` — e.g., `clamav_scan` (WSL) falls back to `windows_defender_scan` (native)
- **Execution flow** (`CyberAgent.execute_tool`):
  1. Look up tool by name
  2. Find available environment (checks WSL, native Windows, or cross-platform)
  3. If environment unavailable → use fallback or skip
  4. **Guardrail check** — auto-approve READ_ONLY; require human approval for MODIFIES_SYSTEM/DESTRUCTIVE unless auto-remediation policy approves
  5. If `python_func` exists → call it directly
  6. Otherwise → construct shell command and run via `execute_system_command`

### C. AI Integration (`key_manager.py`)
- **`AiApi`** is the unified interface for all AI calls
- **Primary**: OmniRoute (local OpenAI-compatible gateway at `http://localhost:20128/v1`)
- **Fallback**: 5 Gemini API keys with round-robin + cooldown on rate limits
- **Demo mode**: `MockRoleKeyManager` returns canned responses for 6 cybersecurity roles
- **Roles**: `threat_intel_analyst`, `malware_analyst`, `network_defender`, `incident_responder`, `forensic_investigator`, `vulnerability_researcher`
- Usage: `api.chat_with_role("threat_intel_analyst", system_prompt, user_prompt)`

### D. CyberAgent Orchestration (`cyber_agent.py`)
The `CyberAgent` class is the central brain:
1. **WSL Detection** — determines which tools can run
2. **Tool Registry** — all 100+ tools registered here
3. **Daemons**:
   - `RealtimeSecurityDaemon` — polls connections, auto-blocks blacklisted IPs
   - `KernelInterceptionDaemon` — low-level network telemetry loop
4. **AI Orchestrators**:
   - `CyberSecurityOrchestrator` — 6 role-based AI agents for threat intel, malware, network, IR, forensics, vuln research
   - `SOCOrchestrator` — 13 specialized SOC agents with keyword-based routing
5. **CyberDB** — JSON-first database for findings/cases/MITRE/workflows
6. **CyberOS** — autonomous live defense engine
7. **Chat Command Processing** — natural language → intent routing → tool execution or AI analysis

### E. Multi-Agent SOC System (`cyber_agent.py` + `cyber_os/`)
- **13 Built-in SOC Agents** (triage, investigator, threat_hunter, correlator, responder, reporter, mitre_analyst, forensics, threat_intel, compliance, malware_analyst, network_analyst, auto_responder)
- **3 Built-in Workflows**:
  - `incident-response` — triage → investigate → contain → report
  - `threat-hunt` — hunt → analyze → enrich → report
  - `forensic-analysis` — collect → analyze → timeline → report
- **Investigation Ledger** — append-only log of every agent action for explainability
- **Workflow execution**: For each phase, run tools → collect output → call AI agent with context → record in ledger

### F. CyberOS Live Defense (`cyber_os/`)
Real-time autonomous monitoring:
1. **EventMonitor** — reads Windows Security Event Log (4624, 4625, 4688, 4697, 7045, 4104)
2. **NetworkMonitor** — polls `psutil.net_connections()`, detects port scans
3. **ProcessMonitor** — watches for suspicious parent→child chains (e.g., winword→cmd)
4. **FileSystemMonitor** — watches `C:\AEGIS_Test` for ransomware-like mass encryption
5. **PowerShellMonitor** — detects obfuscated PowerShell (`-EncodedCommand`, `IEX`, etc.)
6. **Detection Loop** — applies rules → emits `ThreatAlert` with MITRE mapping + AI reasoning
7. **Response Loop** — for critical threats (score ≥ 8), auto-blocks IPs and kills processes
8. **Dashboard** — live event feed, AI reasoning panel, attack simulation buttons
9. **Attack Sims** — safe scripts that generate real Windows events or local port scans

### G. Database Layer (`cyber_db/`)
- **`CyberDB`** — JSON file-backed database
- **Findings**: CRUD operations, severity/status/data_source filtering
- **Cases**: CRUD + timeline events
- **MITRE**: built-in technique dictionary + keyword matching
- **Workflows/Agents**: metadata from `cyber_agent.py`'s built-in definitions
- Files stored at `cyber_db/data/findings.json` and `cyber_db/data/cases.json`

### H. UI Layer
- **`cyber_main.py`** (CustomTkinter):
  - 3-column layout: sidebar | main tabs | context panel
  - Tabs: Agent (chat), Files, Findings, MITRE, Dashboard, SOC, Tools, Workspace
  - Chat routes queries to: findings handler, MITRE handler, dashboard handler, workspace handler, tool executor, SOC workflow handler, or general AI
  - Event-driven updates via `ui/event_bus.py`
- **`cyber_ui.py`** (legacy tkinter):
  - Left panel: 19 categorized button groups (Scanning, AI Reasoning, SOC Orchestrator, Kernel Defense, IAM/Cloud, Honeypot, CyberOS, Benchmark, Vigil SOC, Data/Enrichment, CyberDB, CyberSOC Core)
  - Right panel: live output console + AI chat interface
  - Findings treeview with severity color coding

---

## 5. Key Design Patterns

- **Tool Registry Pattern** — all tools self-register with environment constraints and risk levels
- **Fallback Routing** — WSL tools gracefully fall back to native Windows equivalents
- **Guardrail/Audit Pattern** — every tool execution is logged to `audit_log.json`; sensitive actions require approval or use auto-remediation policies
- **Mock/Demo Mode** — entire AI layer has a `MockRoleKeyManager` for offline demos
- **Event Bus** — decoupled agent-to-UI communication via `AgentEventBus`
- **Intent Routing** — natural language classified into actionable intents before executing tools
- **JSON-First Storage** — database degrades gracefully from PostgreSQL to JSON files

---

## 6. How to Run

```powershell
python cyber_main.py
```

Requirements: Python 3.12, CustomTkinter, psutil, pywin32 (optional, for Windows event logs), paramiko (for honeypot).

---

## 7. Important Notes for Future AI Assistants

- The project is **heavily Windows-oriented** (PowerShell, Windows Event Log, netsh, taskkill, WSL fallbacks)
- **Most "simulated" tools** return fake data unless connected to real APIs or external binaries
- The **AI layer** defaults to demo/mock mode unless OmniRoute (`localhost:20128`) or Gemini keys are configured
- `cyber_os/` attack simulations **write to `C:\AEGIS_Test`** — only safe if that directory exists and is backed up
- `audit_log.json` is append-only and used for compliance/forensics
- There are **two UI entry points**: `cyber_main.py` (modern, recommended) and `cyber_ui.py` (legacy demo dashboard)
