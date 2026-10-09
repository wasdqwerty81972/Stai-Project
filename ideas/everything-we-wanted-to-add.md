# Everything We Wanted to Add — SVS-Cyber Master Vision

> Consolidated product-vision brainstorm, captured 2026-10-02.
> This is the human free-form `ideas/` brainstorm area; the routine's *structured
> engineering* ledger lives separately in `.claude/IDEAS.md`.

## The six major systems (conceptual core)

```
SVS-CYBER
│
├── 1. SENSE
│      Sensors / listeners / telemetry
│
├── 2. TRIAGE
│      Rules + correlation + LAYA
│
├── 3. THINK
│      Qwen3.5-2B CyberAgent + specialists
│
├── 4. INVESTIGATE
│      Tools + evidence + graphs + threat intel
│
├── 5. DEFEND
│      Firewall / quarantine / isolation / recovery
│
└── 6. PRESENT
       HackerAI-style UI + timeline + approvals
```

Onionize, Linux/mobile support, behavioural protection, sandboxing, ransomware
defence and the watchdog are the big expansion features around that core.

## Everything we wanted to add

* **Onionize / Tor privacy mode** — a button that routes supported traffic through Tor, starting with browser traffic and selected applications rather than immediately trying to tunnel the whole OS. We talked about using a local Tor SOCKS client, showing connection/status information, allowing Normal / Onionized / Isolated modes, and having a fast kill switch if something goes wrong.
* **Large sensor/listener fabric** — we talked about an expandable design of roughly 131 potential sensors, but only implementing around 20–30 important ones first. These would watch processes, files, network connections, DNS, persistence changes, registry activity, startup items, services, scheduled tasks, PowerShell, command-line execution, browser/network behaviour, authentication events, privilege changes, suspicious child processes, removable devices, and similar security events.
* **LAYA fast-triage model** — instead of sending every tiny event to the 2B SVS-Cyber model, a much smaller/faster fine-tuned model would classify events as roughly `benign / maybe / suspicious`. Benign noise gets ignored or logged; `maybe` and `yes` cases get escalated to the main investigation agent. That reduces latency and GPU usage massively.
* **Investigation engine** — SVS-Cyber would build an investigation rather than just respond to one alert. It collects related events, searches historical evidence, checks process relationships, examines files/network behaviour, calls tools, forms hypotheses, verifies them, and continues until it has enough evidence or reaches its investigation limits.
* **Process / behavioural graph** — instead of treating each event individually, SVS would build relationships such as `process → child process → file → domain → IP → registry change`. This gives behaviour-based detection similar to what serious endpoint-security systems use.
* **Windows Process Guardian** — monitor suspicious processes, unusual parent-child relationships, privilege escalation patterns, unsigned/suspicious binaries, process injection indicators, abnormal scripting behaviour, and other runtime anomalies.
* **Network Guardian** — inspect connection metadata, unusual destinations, sudden traffic spikes, DNS anomalies, suspicious ports/protocol behaviour, reputation information, and processes making unexpected connections.
* **File Guardian** — watch important directories and files for unusual creation/modification/deletion patterns, suspicious executables/scripts, rapid mass changes, and other filesystem anomalies.
* **Persistence Guardian** — watch mechanisms commonly used to remain active after reboot, including startup entries, services, tasks, and other persistence-related changes.
* **Adaptive Firewall** — allow the agent to recommend temporary network blocks or isolation when evidence supports it, while routing actual actions through the policy/approval system.
* **Privacy Shield** — combine things like tracking/privacy controls, Onionize, suspicious-connection visibility, DNS monitoring, and application-level network controls into one privacy layer.
* **Ransomware protection engine** — detect behavioural indicators such as extremely rapid file modifications across many directories, suspicious processes touching large numbers of user files, and other high-level ransomware patterns, then trigger isolation/containment.
* **Signature / IOC detection** — maintain known hashes, domains, IPs, filenames, URLs, indicators, and security feeds as one detection layer.
* **Heuristic detection** — detect suspicious combinations of behaviour even when the exact threat has never been seen before.
* **IOA / behaviour detection** — focus on what a program is doing rather than just whether its hash appears in a database.
* **Reputation engine** — combine local observations with threat-intelligence/reputation information for files, domains, IPs, URLs, and possibly certificates.
* **Threat-intelligence integration** — correlate alerts with sources such as CVEs, MITRE ATT&CK, known campaigns/techniques, CISA-style vulnerability data, and whatever curated feeds we decide to support.
* **Sandboxing / detonation** — suspicious files could eventually be evaluated in an isolated environment, with the results cached so the same artifact doesn't need to be analysed repeatedly.
* **Memory/security telemetry** — later-stage capability for detecting suspicious runtime behaviour in memory without making the main agent constantly perform expensive scans.
* **Exploit / attack-surface reduction ideas** — watch patterns associated with exploit behaviour and restrict risky behaviour using configurable protections rather than blindly killing processes.
* **Automated remediation** — once a threat is confirmed, the system could recommend or, when policy permits, perform actions such as isolation, quarantine, network blocking, persistence removal, or reverting certain security-related changes.
* **System Recovery** — keep enough evidence/state to help restore things after containment rather than simply deleting suspicious objects.
* **Quarantine** — suspicious artifacts move into a controlled quarantine rather than being permanently destroyed by default.
* **Machine isolation** — ability to restrict a compromised endpoint's network access while still allowing the security agent to function.
* **SVS watchdog / tamper protection** — monitor the agent itself so malware cannot simply terminate SVS-Cyber, disable its listeners, change its configuration, or silently stop logging.
* **Agent Watch** — health monitoring for listeners, workers, models, event buses and tool services; if part of the defence stack dies unexpectedly, SVS knows.
* **Policy Engine** — actions have different risk levels. Reading logs is easy; changing firewall rules or terminating something is more sensitive. The policy system decides what is allowed automatically and what requires approval.
* **Human approval layer** — HackerAI-style inline approval cards for sensitive actions, integrated with your existing `PolicyEngine`, `GuardrailManager`, and approval workflow.
* **Audit logger** — every significant observation, decision, tool call, approval and remediation action gets recorded so the user can see exactly what happened.
* **Evidence management** — findings aren't just chat text. SVS stores evidence per investigation, tracks provenance, and can build an incident timeline from it.
* **13 specialist agents** — the main CyberAgent can delegate specific tasks to smaller specialists instead of attempting every type of investigation itself.
* **Tool registry** — tools have structured names, parameters, risk levels and environments. Agents select tools through the registry rather than executing arbitrary commands.
* **Bounded autonomous loop** — the agent can investigate iteratively but has limits, context management, stopping conditions and doom-loop detection so it doesn't investigate forever.
* **Context compaction** — old investigation details can be compressed while preserving important evidence so the model doesn't overflow its context window.
* **ECC-style planning and verification** — we wanted to borrow ideas like explicit planning, verification, memory, hooks, introspection, regression testing and security guardrails from agent-harness projects.
* **HackerAI-style UI** — continuous conversation rather than basic chat bubbles, proper Markdown, streamed reasoning/status, inline tool execution cards, plans, findings, approvals, subagents, context usage, retry/cancel, investigation states and evidence timelines.
* **Real-time event streaming** — your FastAPI backend/event bus pushes `investigation_started`, agent states, reasoning/status, tool starts/completions, findings, context usage and responses directly to the UI.
* **Windows integration** — SVS should secure the OS people already use rather than forcing them to install a custom operating system. That became one of the project's strongest positioning ideas: "Why switch OS just to be secure when SVS can defend your current OS?"
* **Linux version** — share the same core agent/investigation architecture but use Linux-specific collectors and security integrations.
* **Mobile companion / mobile version** — initially more of a command centre: alerts, investigations, approvals, device status and remote visibility. Later, mobile-specific security capabilities could be added where the OS allows them.
* **Cross-platform shared core** — agent logic, evidence model, policy engine, tool schemas and UI protocol should remain common while collectors/listeners are platform-specific.
* **Local-first operation** — the small Qwen3.5-2B SVS model handles much of the intelligence locally, with specialist/fast models such as LAYA handling cheaper classifications.
* **Cloud intelligence as optional augmentation** — local security shouldn't completely stop merely because a cloud service is unavailable.
* **Model + agent separation** — the 2B model is deliberately not expected to contain every capability. The intelligence comes from the combination of the model, sensors, tools, investigation loop, memory, policies, specialists and threat intelligence.
