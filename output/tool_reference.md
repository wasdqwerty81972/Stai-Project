# STAI Tool Reference

A categorized catalog of every tool available in the STAI (Cybersecurity AI) platform, including the new `shell_exec` tool.

## Tool Categories at a Glance

| # | Category | Tools |
|---|----------|-------|
| 1 | Workspace Access | 2 |
| 2 | Python & Diagnostics | 2 |
| 3 | Anti-Malware Scanning | 10 |
| 4 | Reconnaissance & Network Analysis | 26 |
| 5 | Vulnerability & Malware Scanning | 11 |
| 6 | Static & Dynamic Code Analysis (SAST/DAST) | 8 |
| 7 | File & System Integrity | 16 |
| 8 | Forensics & Incident Response | 13 |
| 9 | Pentesting / Authorized Testing | 4 |
| 10 | Windows Native Cmdlets | 6 |
| 11 | Secret Scanning & Dependencies | 6 |
| 12 | AI-Integrated Security | 5 |
| 13 | Behavioral Detection | 3 |
| 14 | Network Deep Inspection | 3 |
| 15 | Phishing & Social Engineering Detection | 3 |
| 16 | Compliance & Config Auditing | 4 |
| 17 | Remediation (Gated) | 5 |
| 18 | Report Generation | 1 |
| 19 | IAM & Cloud Security | 4 |
| 20 | Honeypot SSH Server | 3 |
| 21 | Quantum-Ready Crypto Audit | 1 |
| 22 | Benchmark / Evaluation | 1 |
| 23 | CyberDB (optional) | 18 |
| 24 | Vigil SOC Workflow Tools (optional) | 8 |
| 25 | CyberSOC Engine Core (optional) | 12 |
| 26 | OSINT / Web Recon / Email / TLS / Cloud (optional) | 20 |
| 27 | Generic Shell Execution | 1 |
| 28 | Process Anomaly Detection | 3 |
| | **Total documented** | **~199** |
| | **Unique runtime tools** | **207** |

---

## Architecture Overview

STAI has two tool sources:

| Source | Mechanism | Count |
|--------|-----------|-------|
| **Built-in default tools** | Registered in `register_all_default_tools()` in `cyber_tools.py` — command-template or Python callables | 168 |
| **Dynamic plugins** | Auto-discovered from `Tools_cyber/*.py` via `register_dynamic_cyber_tools()` — subclasses of `CyberToolPlugin` with `TOOL_CLASS` | 40 |
| **Optional integrations** | Lazily imported (`cyber_db`, `vigil_tools`, `cyber_soc_engine`) — skipped if deps unavailable | 38 (included in built-ins) |

All tools flow through the same pipeline:

1. **Environment routing** — `ToolRegistry.is_environment_available()` checks `cross_platform` / `native_windows` / `wsl_linux`
2. **Guardrail approval** — `AutomatedGuardrailManager` auto-approves `READ_ONLY` tools; `MODIFIES_SYSTEM` / `DESTRUCTIVE` require explicit operator confirmation or a `threat_score ≥ 8`
3. **Execution** — Python callables run directly; `command_template` tools run through `execute_system_command()` → `subprocess.run()` with timeout + cancellation (WSL via `wsl.exe bash -c`, PowerShell via `powershell.exe`, CMD via `cmd.exe /c`)
4. **Audit logging** — every registration, routing decision, and execution is written to `audit_log.json`
5. **UI events** — `tool_started`, `tool_completed`, `tool_failed`, `agent_reasoning` published to the `event_bus`

**Risk levels:** `READ_ONLY` (auto-approved), `MODIFIES_SYSTEM` (needs approval), `DESTRUCTIVE` (needs approval)

---

## Tool Categories

### 1. Workspace Access

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `workspace_list_files` | READ_ONLY | cross | Lists files in the workspace with fnmatch pattern filtering |
| `workspace_read_file` | READ_ONLY | cross | Reads a file from the workspace (up to 1 MB) |

### 2. Python & Diagnostics

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `static_analysis` | READ_ONLY | cross | SAST: detects `eval`/`exec`, `subprocess` calls, and other dangerous patterns in Python source |
| `network_inspect` | READ_ONLY | cross | Inspects active TCP/UDP connections with PID and process info |

### 3. Anti-Malware Scanning (Fallback Pairs)

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `nmap_scan` | READ_ONLY | native_windows or wsl_linux | Network port/service scanner (auto-routes to WSL if native nmap absent) |
| `clamav_scan` → `windows_defender_scan` | READ_ONLY | wsl → native (fallback) | ClamAV file scan; falls back to Windows Defender if WSL/nmap unavailable |
| `windows_defender_scan` | READ_ONLY | native_windows | Runs Defender MpCmdRun.exe on a target file |
| `rkhunter_scan` → `autoruns_scan` | READ_ONLY | wsl → native (fallback) | Linux rootkit detection; falls back to Autoruns scan |
| `autoruns_scan` | READ_ONLY | native_windows | Lists Windows autorun entries, startup items, and services |
| `startup_entries_list` *(plugin)* | READ_ONLY | cross | List and inspect Windows startup entries |
| `aide_check` → `powershell_file_hash` | READ_ONLY | wsl → native (fallback) | AIDE file integrity check; falls back to PowerShell file hashing |
| `powershell_file_hash` | READ_ONLY | native_windows | Computes hashes for all files under a path via `Get-FileHash` |
| `auditd_monitor` → `windows_process_monitor` | READ_ONLY | wsl → native (fallback) | Linux auditd execve log; falls back to Windows process listing |
| `windows_process_monitor` | READ_ONLY | native_windows | Lists running processes with PID, name, and path |
| `tripwire_check` | READ_ONLY | wsl_linux | Tripwire integrity check (no fallback pair) |

### 4. Reconnaissance & Network Analysis

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `tshark_capture` | READ_ONLY | wsl, native | Packet capture with interface/count selection |
| `netcat_test` | READ_ONLY | wsl, native | TCP/UDP port connectivity test |
| `masscan_scan` | READ_ONLY | wsl (admin) | Full-range mass port scanner |
| `arp_scan` | READ_ONLY | wsl (admin) | Local-network ARP discovery |
| `netdiscover` | READ_ONLY | wsl (admin) | Passive/Active ARP reconnaissance |
| `traceroute` | READ_ONLY | wsl, native | Network path tracing |
| `ping` | READ_ONLY | cross | ICMP echo (platform-adaptive) |
| `nslookup` | READ_ONLY | cross | DNS lookup via system resolver |
| `dig` | READ_ONLY | wsl | Advanced DNS record querying |
| `nikto` | READ_ONLY | wsl | Web server vulnerability scanner |
| `dns_lookup` *(plugin)* | READ_ONLY | cross | Resolve A, AAAA, MX, TXT records via dnspython |
| `reverse_dns` *(plugin)* | READ_ONLY | cross | PTR record reverse DNS lookup |
| `subdomain_bruteforce` *(plugin)* | READ_ONLY | cross | Brute-force subdomains with a wordlist |
| `whois_lookup` *(plugin)* | READ_ONLY | cross | WHOIS registration lookup |
| `geo_ip_lookup` *(plugin)* | READ_ONLY | cross | IP-to-geography mapping |
| `ssl_cert_info` *(plugin)* | READ_ONLY | cross | Fetch and parse TLS certificate details |
| `mac_address_lookup` *(plugin)* | READ_ONLY | cross | MAC vendor/OUI lookup |
| `network_adapter_list` *(plugin)* | READ_ONLY | cross | List network interfaces and addresses |
| `http_header_fetch` *(plugin)* | READ_ONLY | cross | Fetch HTTP response headers from a URL |
| `http_header_analyzer` *(plugin)* | READ_ONLY | cross | Analyze headers for security issues |
| `tech_fingerprint_tool` *(plugin)* | READ_ONLY | cross | Identify web technologies from banners/Wappalyzer-style |
| `robots_parser` *(plugin)* | READ_ONLY | cross | Parse robots.txt for disallowed paths |
| `url_validator` *(plugin)* | READ_ONLY | cross | Validate URL syntax and check for dangerous schemes |
| `service_enumeration` *(plugin)* | READ_ONLY | cross | Banner-grab services on open ports |
| `traceroute_simple` *(plugin)* | READ_ONLY | cross | TCP-based simple traceroute |
| `port_scan` *(plugin)* | READ_ONLY | cross | TCP connectivity test to a specific host:port |

### 5. Vulnerability & Malware Scanning

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `yara_scan` | READ_ONLY | wsl, native | YARA pattern matching against files |
| `osv_scanner` | READ_ONLY | cross | OSV database vulnerability scanner |
| `grype_scan` | READ_ONLY | cross | Grype vulnerability scanner for dependencies |
| `trivy_scan` | READ_ONLY | cross | Trivy filesystem/container scanner |
| `openvas_scan` | READ_ONLY | wsl | OpenVAS/Greenbone remote vulnerability scan |
| `virustotal_scan` | READ_ONLY | cross | VirusTotal file/URL scan via `vt` CLI |
| `chkrootkit_scan` | READ_ONLY | wsl (admin) | Chkrootkit local rootkit detector |
| `virustotal_hash_lookup` | READ_ONLY | cross | VT hash reputation lookup (Python API) |
| `urlscan_check` | READ_ONLY | cross | Submit URL to urlscan.io and retrieve results |
| `abuseipdb_check` | READ_ONLY | cross | IP reputation lookup via AbuseIPDB |
| `shodan_lookup` | READ_ONLY | cross | Shodan host/service intelligence lookup |
| `virustotal_ip_lookup` | READ_ONLY | cross | VT IP reputation lookup |
| `otx_ip_lookup` | READ_ONLY | cross | AlienVault OTX IP reputation lookup |
| `enrich_artifact` | READ_ONLY | cross | Enrich artifact with threat intel context |

### 6. Static & Dynamic Code Analysis (SAST/DAST)

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `bandit_scan` | READ_ONLY | cross | Python security linter (B1xx–B6xx rules) |
| `semgrep_scan` | READ_ONLY | cross | Semgrep static analysis with p/security-audit rules |
| `codeql_analyze` | READ_ONLY | cross | CodeQL database analysis → SARIF |
| `eslint_security` | READ_ONLY | cross | ESLint JS security lint via npx |
| `pylint_check` | READ_ONLY | cross | Pylint code quality + security checks |
| `flake8_check` | READ_ONLY | cross | Flake8 style + security linting |
| `cppcheck_scan` | READ_ONLY | cross | Cppcheck C/C++ analysis |
| `gosec_scan` | READ_ONLY | cross | Go security linter (Gosec) |

### 7. File & System Integrity

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `sha256sum` | READ_ONLY | cross | Compute SHA-256 (cross-platform) |
| `hashdeep` | READ_ONLY | wsl | Recursive multi-hash (MD5/SHA1/SHA256) |
| `sysmon_query` | READ_ONLY | native_windows | Query Sysmon operational event log |
| `file_metadata_reader` *(plugin)* | READ_ONLY | cross | Read file metadata (timestamps, permissions, size) |
| `open_files_check` *(plugin)* | READ_ONLY | cross | List currently open files/handles |
| `system_uptime` *(plugin)* | READ_ONLY | cross | Report system boot/uptime |
| `file_type_identifier` *(plugin)* | READ_ONLY | cross | Identify file type via magic bytes |
| `hash_identifier` *(plugin)* | READ_ONLY | cross | Identify hash format from a hash string |
| `hex_tool` *(plugin)* | READ_ONLY | cross | Hex encode/decode converter |
| `base32_tool` *(plugin)* | READ_ONLY | cross | Base32 encode/decode |
| `base64_tool` *(plugin)* | READ_ONLY | cross | Base64 encode/decode (with URL-safe mode) |
| `rot13_tool` *(plugin)* | READ_ONLY | cross | ROT13 cipher |
| `url_encoder` *(plugin)* | READ_ONLY | cross | URL encode/decode |
| `jwt_decoder` *(plugin)* | READ_ONLY | cross | Decode and inspect JWT payloads |
| `cert_fingerprint` *(plugin)* | READ_ONLY | cross | Extract/validate certificate fingerprints |

### 8. Forensics & Incident Response

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `volatility_memory` | READ_ONLY | cross | Volatility memory forensics (`vol -f <image> <plugin>`) |
| `sleuthkit_fls` | READ_ONLY | cross | The Sleuth Kit file listing from disk images |
| `plaso_log2timeline` | READ_ONLY | wsl | Plaso/super-timeline creation from images |
| `strings_inspect` | READ_ONLY | cross | Extract ASCII/Unicode strings from binaries |
| `exiftool_inspect` | READ_ONLY | cross | Extract EXIF/metadata from files |
| `binwalk_inspect` | READ_ONLY | wsl | Firmware/image analysis with binwalk |
| `capa_detect` | READ_ONLY | cross | Capa malware capability rule matching |
| `pe_analyzer` *(plugin)* | READ_ONLY | cross | Parse PE headers, sections, imports |
| `elf_analyzer` *(plugin)* | READ_ONLY | cross | Parse ELF headers and program headers |
| `pe_header_analysis` | READ_ONLY | cross | Python PE header analysis (pefile-based) |
| `entropy_check` | READ_ONLY | cross | Calculate Shannon entropy of a file |
| `import_table_scan` | READ_ONLY | cross | Flag suspicious DLL imports in PE files |
| `email_validator` *(plugin)* | READ_ONLY | cross | Validate email format and check SMTP records |
| `phone_number_lookup` *(plugin)* | READ_ONLY | cross | Phone number format/country lookup |

### 9. Pentesting / Authorized Testing

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `metasploit_console` | **DESTRUCTIVE** | wsl | Metasploit console (approved only for authorized testing) |
| `zap_cli_scan` | MODIFIES_SYSTEM | cross | OWASP ZAP automated web scanner |
| `sqlmap_scan` | MODIFIES_SYSTEM | cross | SQL injection detection/exploitation |
| `hydra_test` | MODIFIES_SYSTEM | wsl | Brute-force login testing (password lists) |
| `xss_scanner` *(plugin)* | READ_ONLY | cross | Reflected/stored XSS payload testing |
| `sqli_scanner` *(plugin)* | READ_ONLY | cross | SQL injection pattern detection |
| `path_traversal_tester` *(plugin)* | READ_ONLY | cross | Path traversal payload testing |

### 10. Windows Native Cmdlets & Utilities

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `get_winevent` | READ_ONLY | native_windows | Query Windows Event Log |
| `get_service` | READ_ONLY | native_windows | List Windows services and status |
| `psscriptanalyzer` | READ_ONLY | native_windows | PowerShell script static analysis |
| `wmic_query` | READ_ONLY | native_windows | WMI system information queries |
| `netsh_query` | READ_ONLY | native_windows | Network interface configuration |
| `sc_query` | READ_ONLY | native_windows | Service control manager queries |

### 11. Secret Scanning & Dependencies

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `secret_scan` | READ_ONLY | cross | Regex-based secret/credential detection |
| `improved_secret_scan` | READ_ONLY | cross | Enhanced secret scanner (functional OSINT layer) |
| `dependency_check` | READ_ONLY | cross | Analyze Python requirements.txt for known CVEs |
| `password_generator` *(plugin)* | READ_ONLY | cross | Generate cryptographically random passwords |
| `user_agent_parser` *(plugin)* | READ_ONLY | cross | Parse User-Agent strings into components |
| `regex_tester` *(plugin)* | READ_ONLY | cross | Test regex patterns against sample text |

### 12. AI-Integrated Security Tools

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `ai_secure_fix` | READ_ONLY | cross | AI-generated code security patches |
| `ai_incident_summary` | READ_ONLY | cross | AI-generated incident response summary |
| `ai_yara_generator` | READ_ONLY | cross | AI-generated YARA detection rules |
| `ai_triage_correlate` | READ_ONLY | cross | AI-based finding correlation and scoring |
| `ai_explain_risk` | READ_ONLY | cross | AI risk explanation for code findings |
| `ai_anomaly_baseline` | READ_ONLY | cross | Statistical anomaly detection against baselines |

### 13. Behavioral Detection

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `sigma_rule_match` | READ_ONLY | native_windows | Match Sysmon/process logs against Sigma rules |
| `process_tree_analysis` | READ_ONLY | native_windows | Analyze parent-child process trees |
| `suspicious_parent_child` | READ_ONLY | cross | Flag suspicious process lineage chains |

### 14. Network Deep Inspection

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `dns_exfil_check` | READ_ONLY | cross | Detect DNS tunneling/exfiltration patterns |
| `beaconing_detect` | READ_ONLY | cross | Detect periodic C2 callback patterns |
| `tls_cert_check` | READ_ONLY | cross | Inspect TLS certificate validity/chain |

### 15. Phishing & Social Engineering Detection

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `email_header_analysis` | READ_ONLY | cross | Analyze email headers for spoofing/anomalies |
| `url_similarity_check` | READ_ONLY | cross | Typosquat/homoglyph domain detection |
| `attachment_macro_scan` | READ_ONLY | cross | Extract and analyze Office document macros |

### 16. Compliance & Config Auditing

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `cis_benchmark_check` | READ_ONLY | native_windows | CIS Windows benchmark configuration audit |
| `firewall_rule_audit` | READ_ONLY | native_windows | Enumerate active Windows Firewall rules |
| `open_port_audit` | READ_ONLY | cross | Audit listening TCP/UDP ports |
| `password_policy_check` | READ_ONLY | native_windows | Query Windows password policy settings |

### 17. Remediation (Gated)

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `quarantine_file` | MODIFIES_SYSTEM | cross | Move a file to a quarantine directory |
| `disable_startup_entry` | **DESTRUCTIVE** | native_windows | Remove a Windows autorun/startup entry |
| `revert_registry_key` | **DESTRUCTIVE** | native_windows | Restore a registry key from backup |
| `terminate_process` | **DESTRUCTIVE** | cross | Kill a process by PID |
| `block_ip` | MODIFIES_SYSTEM | cross | Block an IP via host firewall |
| `kill_and_block` | **DESTRUCTIVE** | cross | Terminate process and firewall-block IP |

### 18. Report Generation

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `generate_incident_report` | READ_ONLY | cross | Build a structured incident summary PDF/markdown |

### 19. IAM & Cloud Security (optional)

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `active_directory_privilege_audit` | READ_ONLY | native_windows | Enumerate AD users and privileged accounts |
| `ssh_key_auditor` | READ_ONLY | cross | Scan for exposed SSH keys (simulated) |
| `s3_bucket_leak_checker` | READ_ONLY | cross | Check S3 bucket public access (simulated) |
| `container_security_audit` | READ_ONLY | cross | Container image security audit (simulated) |

### 20. Honeypot SSH Server

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `start_honeypot` | READ_ONLY | cross | Start the simulated SSH honeypot |
| `stop_honeypot` | READ_ONLY | cross | Stop the honeypot |
| `honeypot_status` | READ_ONLY | cross | Query honeypot status, connections, logs |

### 21. Quantum-Ready Crypto Audit

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `quantum_ready_audit` | READ_ONLY | cross | Audit crypto algorithms for post-quantum readiness |

### 22. Benchmark / Evaluation

| Tool | Risk | Environment | What it does |
|------|------|-------------|-------------|
| `benchmark_run` | READ_ONLY | cross | Run STAI evaluation benchmarks |

### 23. CyberDB (optional — JSON-first database)

All gated behind `cyber_db` import availability.

| Tool | Risk | What it does |
|------|------|-------------|
| `db_add_finding` | MODIFIES_SYSTEM | Create a new finding record |
| `db_get_finding` | READ_ONLY | Retrieve a finding by ID |
| `db_list_findings` | READ_ONLY | List findings with filters |
| `db_update_finding` | MODIFIES_SYSTEM | Update an existing finding |
| `db_delete_finding` | DESTRUCTIVE | Delete a finding |
| `db_create_case` | MODIFIES_SYSTEM | Create a new case |
| `db_get_case` | READ_ONLY | Retrieve a case by ID |
| `db_list_cases` | READ_ONLY | List cases with filters |
| `db_update_case` | MODIFIES_SYSTEM | Update case metadata |
| `db_add_case_event` | MODIFIES_SYSTEM | Append an event to a case timeline |
| `db_map_mitre` | READ_ONLY | Map a finding to MITRE ATT&CK techniques |
| `db_get_mitre_techniques` | READ_ONLY | Query MITRE techniques by keyword |
| `db_list_workflows` | READ_ONLY | List stored workflow definitions |
| `db_get_workflow` | READ_ONLY | Retrieve a workflow by ID |
| `db_list_agents` | READ_ONLY | List registered SOC agents |
| `db_get_agent` | READ_ONLY | Get agent configuration |
| `db_get_stats` | READ_ONLY | Database-wide statistics |
| `db_get_findings_count` | READ_ONLY | Count of total findings |

### 24. Vigil SOC Workflow Tools (optional)

| Tool | Risk | What it does |
|------|------|-------------|
| `soc_generate_sample_data` | READ_ONLY | Generate sample SOC data (10 events, 2 alerts) |
| `soc_save_sample_data` | READ_ONLY | Save sample data to files |
| `soc_enrich_findings` | READ_ONLY | Enrich findings with context data |
| `soc_compile_workflow` | READ_ONLY | Compile a markdown workflow into structured phases |
| `soc_validate_workflow` | READ_ONLY | Validate workflow definition for errors |
| `soc_create_workflow` | READ_ONLY | Create a new workflow definition |
| `soc_init_schema` | MODIFIES_SYSTEM | Initialize the SOC database schema |
| `soc_seed_reference_data` | MODIFIES_SYSTEM | Seed reference data (MITRE, Sigma rules) |

### 25. CyberSOC Engine Core (optional)

| Tool | Risk | What it does |
|------|------|-------------|
| `soc_get_secret` | READ_ONLY | Retrieve an encrypted secret |
| `soc_set_secret` | MODIFIES_SYSTEM | Store an encrypted secret |
| `soc_delete_secret` | DESTRUCTIVE | Delete a stored secret |
| `soc_init_telemetry` | READ_ONLY | Initialize OpenTelemetry tracing |
| `soc_set_investigation_id` | READ_ONLY | Set the current investigation correlation ID |
| `soc_get_investigation_id` | READ_ONLY | Get the current investigation ID |
| `soc_get_integration_config` | READ_ONLY | Get third-party integration configuration |
| `soc_is_integration_enabled` | READ_ONLY | Check if an integration is enabled |
| `soc_get_general_config` | READ_ONLY | Get a general configuration value |
| `soc_utcnow` | READ_ONLY | Get current UTC time |
| `soc_get_version` | READ_ONLY | Get CyberSOC engine version |
| `soc_rate_limit_check` | READ_ONLY | Check rate limiter bucket status |

### 26. Functional OSINT / Web Recon / Email / TLS / Cloud (optional)

| Tool | Risk | What it does |
|------|------|-------------|
| `osint_subdomain_enum` | READ_ONLY | Enumerate subdomains for a domain |
| `osint_reverse_dns` | READ_ONLY | Reverse DNS lookup |
| `osint_dns_enum` | READ_ONLY | DNS record enumeration (A, MX, TXT, etc.) |
| `osint_cloudflare_check` | READ_ONLY | Check if domain is behind Cloudflare |
| `web_security_headers` | READ_ONLY | Fetch and analyze HTTP security headers |
| `web_robots_txt` | READ_ONLY | Fetch and parse robots.txt |
| `web_tech_fingerprint` | READ_ONLY | Fingerprint web technologies (Wappalyzer-style) |
| `web_sensitive_paths` | READ_ONLY | Check for common sensitive paths |
| `email_security_posture` | READ_ONLY | Comprehensive email security posture analysis |
| `email_spf_check` | READ_ONLY | SPF record validation |
| `email_dmarc_check` | READ_ONLY | DMARC policy check |
| `email_dkim_check` | READ_ONLY | DKIM key validation |
| `tls_cert_inspect` | READ_ONLY | TLS certificate inspection |
| `tls_config_check` | READ_ONLY | TLS configuration analysis |
| `tls_ct_logs` | READ_ONLY | Certificate Transparency log lookup |
| `cloud_s3_check` | READ_ONLY | Check S3 bucket public exposure |
| `cloud_azure_check` | READ_ONLY | Check Azure blob public access |
| `cloud_gcp_check` | READ_ONLY | Check GCP bucket public access |
| `cloud_exposed_admin` | READ_ONLY | Find exposed admin panels |

### 27. Generic Shell Execution ← NEW

| Tool | Risk | Environments | What it does |
|------|------|-------------|-------------|
| `shell_exec` | MODIFIES_SYSTEM | cross | Execute arbitrary PowerShell / WSL / CMD commands |

**Arguments:**
- `command` (required, str): The command string to execute
- `environment` (default `"powershell"`, str): One of `"powershell"`, `"wsl"`, `"cmd"`
- `timeout` (default `15`, int): Max execution seconds (hard-capped at 300)

**How it works:**
1. Delegates to the existing `execute_system_command()` in `cyber_tools.py`
2. Routes through `powershell.exe`, `wsl.exe bash -c`, or `cmd.exe /c`
3. Gated at `MODIFIES_SYSTEM` → requires guardrail approval (auto-approved for read-only commands via the automated guardrail manager; otherwise prompts the operator or auto-remediates if `threat_score ≥ 8`)
4. Full audit logging and UI event publishing
5. Timeout enforcement and cancellation support via `self.cancel_event`

**Usage via CLI:**
```bash
python cyber_tools_template.py call shell_exec --input '{"command": "Get-Process", "environment": "powershell"}'
python cyber_tools_template.py call shell_exec --input '{"command": "ls -la /tmp", "environment": "wsl"}'
python cyber_tools_template.py call shell_exec --input '{"command": "net user", "environment": "cmd"}'
```

---

### 28. Process Anomaly Detection

| Tool | Risk | What it does |
|------|------|-------------|
| `detect_cpu_spikes` | READ_ONLY | Identify high-CPU processes |
| `detect_memory_hogs` | READ_ONLY | Detect unusual memory consumption |
| `audit_background_services` | READ_ONLY | Audit hidden background services |

---

## CyberOS Autonomous Defense System

In addition to the tool catalog, STAI includes the **CyberOS** autonomous defense engine (`cyber_os/`), which provides:

| Component | File | Role |
|-----------|------|------|
| `CyberOSEngine` | `cyber_os/engine.py` | Event-driven threat detection engine (60+ rules mapping to MITRE ATT&CK techniques) |
| `CyberOSAI` | `cyber_os/cyber_os_ai.py` | AI reasoning layer for alert analysis with template fallback |
| `CyberOSDashboard` | `cyber_os/cyber_os_dashboard.py` | Web dashboard for real-time threat visualization |
| `InvestigationState` | `cyber_os/investigation_state.py` | Investigation case state management |
| `AttackSimulations` | `cyber_os/cyber_os_attacks.py` | Safe attack simulations (bruteforce, PowerShell obfuscation, portscan, ransomware) |
| `NemoAgentToolkit` | `cyber_os/nemo_agent_toolkit.py` | Integration with NVIDIA NeMo framework |
| `AgentBus` | `cyber_os/agent_bus.py` | Inter-agent message bus for SOC coordination |
| `IntentRouter` | `cyber_os/intent_router.py` | AI intent classification and route selection |
| `CorrelationEngine` | `cyber_os/correlation_engine.py` | Alert correlation and enrichment |
| `MITRE Engine` | `cyber_os/mitre_engine.py` | MITRE ATT&CK mapping and analysis |
| `PolicyEngine` | `cyber_os/policy_engine.py` | Security policy enforcement |
| `ResponseEngine` | `cyber_os/response_engine.py` | Automated response action execution |
| `CyberOSSOC` | `cyber_os/cyber_os_soc.py` | SOC integration layer |

## Daemons (Real-time Monitoring)

| Daemon | What it does |
|--------|-------------|
| `RealtimeSecurityDaemon` | Background thread polling network connections; auto-blocks blacklisted IPs and terminates associated malicious processes |
| `KernelInterceptionDaemon` | Event-driven telemetry monitoring; alerts on blacklisted endpoint connections |

## 13 Specialized SOC Agents

Defined in `cyber_agent.py` as `SOCAgent` dataclass instances, each with a specific role:
1. `triage` — Initial alert scoring and false-positive filtering
2. `investigator` — Evidence collection and timeline reconstruction
3. `responder` — Containment actions (quarantine, block, disable)
4. `reporter` — Incident report generation
5. `threat_hunter` — Proactive hypothesis-driven hunting
6. `malware_analyst` — Binary analysis and IOC extraction
7. `forensics` — Evidence preservation and chain of custody
8. `threat_intel_analyst` — Threat intelligence and attribution
9. `network_defender` — Network traffic analysis and firewall rules
10. `vulnerability_researcher` — CVE assessment and patch recommendations
11. `compliance_auditor` — CIS/NIST compliance checking
12. `vulnerability_researcher` — Exploitation feasibility analysis
13. `agent_orchestrator` — Multi-agent coordination and workflow execution
