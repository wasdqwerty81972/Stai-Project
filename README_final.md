wasdqwerty
supreme
27918
wasdqwertysu


# CyberAgent - Native Desktop Workspace

## System Status
- Native PySide6 desktop application
- Chat-first agent workspace inspired by the `venkat-ideas` design
- Existing Python security tools and CyberOS remain behind the agent
- No browser frontend and no Tkinter launch path
- Optional NeMo Agent Toolkit compatibility for tool manifests and workflows

## How to Run
1. Use the existing system Python 3.11+ installation.
2. Install the native desktop binding once:
```
python -m pip install PySide6
```
3. Run from the project directory:
```
python cyber_main.py
```

## Requirements
- Python 3.11+
- PySide6
- PostgreSQL is optional; the bundled JSON database is used when it is unavailable.

NeMo Agent Toolkit is optional. The project exposes its existing tool catalog and
security metadata through `cyber_os/nemo_agent_toolkit.py`; the native PySide6 UI
remains the presentation layer. Install `nvidia-nat` only when you want to run
NAT workflows or profiling alongside the local agent:

```
python -m pip install nvidia-nat
```

## Troubleshooting
- The prompt is the primary control. Press Enter to send and Shift+Enter for a new line.
- The right context rail reports the current session, capabilities, findings, and environment.
- If the live AI provider is unavailable, the agent falls back to its local/mock mode.

Run a complete read-only SOC validation investigation on this workstation.

Your goal is to verify that every specialist agent, workflow phase, tool-routing path, NAT execution path, evidence pipeline, and reporting step is working correctly.

Use all available SOC specialists where applicable:

1. Triage Agent
   - Classify the investigation priority.
   - Explain the investigation scope and success criteria.

2. Investigation Agent
   - Coordinate the overall investigation.
   - Verify that every phase produces a result.

3. Network Analyst
   - Inspect active network connections.
   - Inspect listening ports and suspicious network activity.
   - Record the actual tool used and its output.

4. Threat Hunter
   - Look for anomalies, beaconing behavior, DNS exfiltration indicators, and unusual connections.
   - Clearly distinguish confirmed evidence from hypotheses.

5. Malware Analyst
   - Scan the workspace for suspicious files, encoded content, secrets, persistence indicators, and malware-related artifacts.
   - Do not claim malware was detected unless a real tool reports it.

6. Threat Intelligence Analyst
   - Enrich any IP addresses, domains, hashes, or other indicators discovered during the investigation.
   - State when enrichment is unavailable or inconclusive.

7. Forensics Agent
   - Inspect relevant artifacts and reconstruct an evidence timeline.
   - Preserve evidence references without modifying files.

8. MITRE Analyst
   - Map only confirmed observed behaviors to MITRE ATT&CK techniques.
   - Do not invent mappings.

9. Correlator
   - Correlate network, process, file, and finding data.
   - Identify whether multiple signals support the same incident.

10. Compliance Agent
    - Evaluate the observed state against relevant security controls.
    - Mention missing evidence instead of guessing compliance status.

11. Incident Responder
    - Assess severity, blast radius, and containment recommendations.
    - Do not block IPs, quarantine files, terminate processes, delete files, or modify the system.

12. Reporter
    - Produce a final technical and executive report.

13. Auto Responder
    - Validate that approval gates work.
    - Do not execute any remediation action.
    - Show which actions would require approval.

Run a populated investigation workflow, not only a workflow compilation step. Do not call the workflow compiler with an empty definition. If a workflow definition is required, use the built-in incident-response workflow or create a populated workflow containing real phases.

During execution, show all of the following:

- Investigation objective
- Intent classification
- Selected specialist agent
- Specialist reasoning summary
- Selected tool
- Tool arguments
- Tool environment
- Tool start event
- Live tool output
- Tool completion or failure event
- Evidence collected
- Findings created
- Workflow phase status
- Approval requirements
- NAT execution status
- Correlation results
- MITRE mappings
- Investigation timeline

Verify that the following tool categories are exercised when supported by the current environment:

- Network connection inspection
- Process inspection
- Workspace/file analysis
- Secret scanning
- Malware or Windows Defender scanning
- Hash or IOC enrichment
- MITRE mapping
- Finding/database operations
- Incident report generation

Use real tools and real system evidence. Do not use fake, canned, simulated, or placeholder findings.

At the end, provide a validation matrix with these columns:

- Component
- Specialist
- Tool or workflow phase
- Status
- Evidence produced
- Error details
- Approval required

Then provide:

- Executive summary
- Confirmed findings
- Unconfirmed hypotheses
- Tools successfully executed
- Tools unavailable and why
- Agents successfully invoked
- Workflow phases successfully completed
- NAT runtime status
- GPU/CUDA acceleration status
- MITRE ATT&CK mappings
- Recommended next steps
- Actions requiring approval
- Clear statement of whether a threat was confirmed

This is a read-only validation. Do not modify, delete, quarantine, terminate, block, disable, or remediate anything.