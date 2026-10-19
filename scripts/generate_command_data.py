"""One-off generator: emit cyber_os/command_presets.py and
cyber_os/policy/command_rules.yaml from the LIVE tool registry.

Run:  python scripts/generate_command_data.py

This is intentionally not a package module and imports cyber_tools directly.
The emitted command_presets.py must NOT import cyber_tools (avoids a cycle),
so all values are frozen into literals here.
"""
from __future__ import annotations

import io
import json
import os
import re
import shlex
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from cyber_tools import (  # noqa: E402
    ToolRegistry,
    AuditLogger,
    register_all_default_tools,
    RiskLevel,
)

PRESETS_PY = os.path.join(ROOT, "cyber_os", "command_presets.py")
POLICY_DIR = os.path.join(ROOT, "cyber_os", "policy")
RULES_YAML = os.path.join(POLICY_DIR, "command_rules.yaml")

# Risk ordering for taking the MAX when merging rows onto one binary.
RISK_ORDER = {
    "READ_ONLY": 0,
    "MODIFIES_SYSTEM": 1,
    "DESTRUCTIVE": 2,
    "KERNEL_INTERVENTION": 3,
}
INTERP_CANON = ["bash", "cmd", "powershell"]

# ---- Authored fields (the only genuinely hand-written data) ----------------
# summary: short human phrase. ToolDefinition has no description today.
SUMMARIES = {
    "active_directory_privilege_audit": "Enumerate Active Directory user accounts and enabled status",
    "aide_check": "Verify filesystem integrity against the AIDE baseline database",
    "arp_scan": "Discover live hosts on the local subnet via ARP",
    "auditd_monitor": "Review Linux auditd execve (process execution) records",
    "autoruns_scan": "List Windows auto-start entries (Sysinternals autorunsc)",
    "bandit_scan": "Static security scan of a Python source tree (Bandit)",
    "binwalk_inspect": "Analyze a firmware/binary blob for embedded files (binwalk)",
    "capa_detect": "Identify malware capabilities in a binary (capa)",
    "chkrootkit_scan": "Scan the local system for known rootkits (chkrootkit)",
    "clamav_scan": "Recursive antivirus scan of a path (ClamAV)",
    "codeql_analyze": "Run CodeQL security queries against a prebuilt database",
    "cppcheck_scan": "Static analysis of C/C++ source (cppcheck)",
    "dig": "DNS record lookup for a domain (dig)",
    "eslint_security": "Lint JavaScript/TypeScript for security issues (ESLint)",
    "exiftool_inspect": "Extract file metadata (ExifTool)",
    "firewall_rule_audit": "List enabled Windows firewall rules",
    "flake8_check": "Style and lint check of Python source (flake8)",
    "get_service": "List Windows services and their state",
    "get_winevent": "Read recent entries from a named Windows event log",
    "gosec_scan": "Static security scan of a Go module (gosec)",
    "grype_scan": "Scan packages/images for known vulnerabilities (grype)",
    "hashdeep": "Recursively compute file hashes for integrity (hashdeep)",
    "hydra_test": "Online password brute-force test of a service (Hydra)",
    "masscan_scan": "High-speed TCP port sweep of a host or range (masscan)",
    "metasploit_console": "Run a Metasploit console command batch (msfconsole)",
    "netcat_test": "Test TCP connectivity to a host/port (netcat)",
    "netdiscover": "Active host discovery on a subnet (netdiscover)",
    "netsh_query": "Show Windows network interface configuration (netsh)",
    "nikto": "Web server vulnerability scan (Nikto)",
    "nmap_scan": "TCP port and service scan of a host or range (nmap)",
    "nslookup": "DNS name resolution query (nslookup)",
    "openvas_scan": "Query the OpenVAS/GVM scanner for task status",
    "osv_scanner": "Scan a project for known-vulnerable dependencies (OSV)",
    "password_policy_check": "Show local Windows account/password policy",
    "ping": "ICMP reachability check of a host",
    "plaso_log2timeline": "Build a forensic super-timeline from an image (Plaso)",
    "powershell_file_hash": "Recursively hash files under a path (PowerShell Get-FileHash)",
    "process_tree_analysis": "Enumerate processes with parent PID and command line (WMI)",
    "psscriptanalyzer": "Lint a PowerShell script for issues (PSScriptAnalyzer)",
    "pylint_check": "Static analysis of Python source (pylint)",
    "rkhunter_scan": "Scan for rootkits and local backdoors (rkhunter)",
    "sc_query": "Query the state of a Windows service (sc)",
    "semgrep_scan": "Pattern-based static security scan (Semgrep)",
    "sha256sum": "Compute the SHA-256 hash of a file (PowerShell)",
    "sleuthkit_fls": "List files/inodes from a disk image (Sleuth Kit fls)",
    "sqlmap_scan": "Automated SQL injection test of a URL (sqlmap)",
    "strings_inspect": "Extract printable strings from a binary",
    "sysmon_query": "Read recent Sysmon operational event log entries",
    "traceroute": "Trace the network path to a host",
    "tripwire_check": "Verify filesystem integrity against Tripwire policy",
    "trivy_scan": "Scan a filesystem for vulnerabilities and misconfig (Trivy)",
    "tshark_capture": "Capture a bounded number of packets on an interface (tshark)",
    "virustotal_scan": "Look up a file's reputation on VirusTotal (vt-cli)",
    "volatility_memory": "Run a Volatility plugin against a memory image",
    "windows_defender_scan": "On-demand Microsoft Defender scan of a path",
    "windows_process_monitor": "List running processes with image paths (PowerShell)",
    "wmic_query": "Query system info via WMI aliases (wmic)",
    "yara_scan": "Match YARA rules against a file or directory",
    "zap_cli_scan": "Automated web app security scan (OWASP ZAP CLI)",
}

# example args: realistic literals that fill every placeholder for that tool.
# Only tools that HAVE placeholders appear here. Verified for full coverage.
EXAMPLE_ARGS = {
    "bandit_scan": {"target": r"C:\workspace\app"},
    "binwalk_inspect": {"target": "/home/analyst/firmware.bin"},
    "capa_detect": {"target": r"C:\workspace\samples\suspicious.exe"},
    "clamav_scan": {"target": "/home/analyst/quarantine"},
    "codeql_analyze": {"db": r"C:\workspace\codeql-db", "output": r"C:\workspace\results.sarif"},
    "cppcheck_scan": {"target": r"C:\workspace\app\src"},
    "dig": {"domain": "example.com"},
    "eslint_security": {"target": r"C:\workspace\webapp"},
    "exiftool_inspect": {"target": r"C:\workspace\samples\image.jpg"},
    "flake8_check": {"target": r"C:\workspace\app"},
    "get_winevent": {"log_name": "Security"},
    "grype_scan": {"target": r"C:\workspace\app"},
    "hashdeep": {"target": "/home/analyst/evidence"},
    "hydra_test": {"user": "admin", "passlist": "/usr/share/wordlists/rockyou.txt",
                   "target": "10.0.0.1", "service": "ssh"},
    "masscan_scan": {"target": "10.0.0.1", "ports": "1-1000"},
    "metasploit_console": {"command": "version"},
    "netcat_test": {"host": "10.0.0.1", "port": "443"},
    "netdiscover": {"range": "10.0.0.0/24"},
    "nikto": {"target": "10.0.0.1"},
    "nmap_scan": {"target": "10.0.0.1"},
    "nslookup": {"domain": "example.com"},
    "osv_scanner": {"target": r"C:\workspace\app"},
    "ping": {"target": "10.0.0.1"},
    "plaso_log2timeline": {"output": "/home/analyst/timeline.plaso", "image": "/home/analyst/disk.img"},
    "powershell_file_hash": {"target": r"C:\workspace\samples"},
    "psscriptanalyzer": {"target": r"C:\workspace\scripts\deploy.ps1"},
    "pylint_check": {"target": r"C:\workspace\app"},
    "sc_query": {"service": "Spooler"},
    "semgrep_scan": {"target": r"C:\workspace\app"},
    "sha256sum": {"target": r"C:\workspace\samples\suspicious.exe"},
    "sleuthkit_fls": {"image": r"C:\workspace\evidence\disk.raw"},
    "sqlmap_scan": {"url": "http://10.0.0.1/page?id=1"},
    "strings_inspect": {"target": r"C:\workspace\samples\suspicious.exe"},
    "traceroute": {"target": "10.0.0.1"},
    "trivy_scan": {"target": r"C:\workspace\app"},
    "tshark_capture": {"interface": "eth0", "count": "100"},
    "virustotal_scan": {"target": r"C:\workspace\samples\suspicious.exe"},
    "volatility_memory": {"image": r"C:\workspace\evidence\memory.raw", "plugin": "windows.pslist"},
    "windows_defender_scan": {"target": r"C:\workspace\samples"},
    "wmic_query": {"alias": "process", "properties": "Name,ProcessId"},
    "yara_scan": {"rules": r"C:\workspace\rules\malware.yar", "target": r"C:\workspace\samples\suspicious.exe"},
    "zap_cli_scan": {"target": "http://10.0.0.1"},
}


def build_registry():
    logp = os.path.join(tempfile.gettempdir(), "svs_generate_audit.jsonl")
    log = AuditLogger(log_path=logp)
    try:
        log.suppress(True)
    except Exception:
        pass
    reg = ToolRegistry(log)
    register_all_default_tools(reg)
    return reg


def normalize_binary(argv):
    """Return (basename_casefolded_no_exe, probe_unreliable)."""
    tok = argv[0]
    unreliable = False
    # PowerShell call/dot operator: the real target is the next token.
    if tok in ("&", ".") and len(argv) > 1:
        tok = argv[1]
        unreliable = True
    if "{" in tok:
        unreliable = True
    stripped = tok.strip('"').strip("'")
    if stripped != tok:
        unreliable = True  # argv[0] was a quoted path
    tok = stripped
    base = re.split(r"[\\/]", tok)[-1]
    if base.casefold().endswith(".exe"):
        base = base[:-4]
    return base.casefold(), unreliable


def expand_str(template, args):
    """Fill {name} tokens in a plain string; used only to render `example`."""
    def repl(m):
        return str(args[m.group(1)])
    return re.sub(r"\{(\w+)\}", repl, template)


def interps_for(env):
    envs = env if isinstance(env, list) else [env]
    out = []
    for e in envs:
        if e == "wsl_linux":
            cand = ["bash"]
        elif e == "native_windows":
            cand = ["cmd", "powershell"]
        else:  # cross_platform
            cand = ["bash", "cmd", "powershell"]
        for c in cand:
            if c not in out:
                out.append(c)
    return [c for c in INTERP_CANON if c in out]


def main():
    reg = build_registry()
    wrappers = {n: t for n, t in reg.tools.items() if getattr(t, "command_template", "")}
    assert len(wrappers) == 59, f"expected 59 CLI wrappers, got {len(wrappers)}"

    # Sanity: authored maps must cover every live wrapper.
    missing_sum = sorted(set(wrappers) - set(SUMMARIES))
    assert not missing_sum, f"SUMMARIES missing ids: {missing_sum}"

    presets = {}
    rule_src = {}  # binary -> list of dicts describing each contributing preset
    for name in sorted(wrappers):
        t = wrappers[name]
        tmpl = t.command_template
        argv = shlex.split(tmpl, posix=False)
        placeholders = sorted(set(re.findall(r"\{(\w+)\}", tmpl)))
        env = list(t.environments)
        env_val = env[0] if len(env) == 1 else env
        risk = t.risk_level.name
        admin = bool(t.requires_admin)
        fallback = t.fallback_tool or None
        probe_binary, unreliable = normalize_binary(argv)

        # example args: authored for placeholder tools; empty for the rest.
        ex_args = EXAMPLE_ARGS.get(name, {})
        if placeholders:
            miss = sorted(set(placeholders) - set(ex_args))
            assert not miss, f"EXAMPLE_ARGS[{name}] missing {miss}"
        example = expand_str(tmpl, ex_args)

        presets[name] = dict(
            id=name, summary=SUMMARIES[name], env=env_val,
            argv_template=argv, placeholders=placeholders, risk_level=risk,
            requires_admin=admin, probe_binary=probe_binary, example=example,
            fallback_preset=fallback, probe_unreliable=unreliable,
        )

        # ---- rule derivation ----
        allowed_flags = []
        allowed_prefixes = []
        for tok in argv:
            if tok and tok[0] in "-/":
                if "{" in tok:
                    allowed_prefixes.append(tok[: tok.index("{")])
                else:
                    allowed_flags.append(tok)
        rule_src.setdefault(probe_binary, []).append(dict(
            preset=name, flags=allowed_flags, prefixes=allowed_prefixes,
            level=risk, admin=admin, env=env_val,
        ))

    write_presets_py(presets)
    rules, merges = build_rules(rule_src)
    write_rules_yaml(rules, merges)

    print("OK presets=%d rules=%d merges=%d" % (len(presets), len(rules), len(merges)))
    print("wrote", PRESETS_PY)
    print("wrote", RULES_YAML)


def build_rules(rule_src):
    rules = []
    merges = {}  # rule_id -> [preset ids] (only when >1 source)
    for binary in sorted(rule_src):
        srcs = rule_src[binary]
        flags, prefixes, interps = [], [], []
        max_level = "READ_ONLY"
        admin = False
        for s in srcs:
            for f in s["flags"]:
                if f not in flags:
                    flags.append(f)
            for p in s["prefixes"]:
                if p not in prefixes:
                    prefixes.append(p)
            for c in interps_for(s["env"]):
                if c not in interps:
                    interps.append(c)
            if RISK_ORDER[s["level"]] > RISK_ORDER[max_level]:
                max_level = s["level"]
            admin = admin or s["admin"]
        interps = [c for c in INTERP_CANON if c in interps]
        if len(srcs) > 1:
            merges[binary] = sorted(s["preset"] for s in srcs)
            reason = "Read-only %s cmdlets (%d presets); no host mutation" % (
                binary, len(srcs)) if max_level == "READ_ONLY" else \
                "Merged %d presets on %s" % (len(srcs), binary)
        else:
            reason = {
                "READ_ONLY": "Read-only inspection; does not mutate the target",
                "MODIFIES_SYSTEM": "Actively probes and may alter the target",
                "DESTRUCTIVE": "Can run arbitrary or destructive operations",
                "KERNEL_INTERVENTION": "Operates at kernel level",
            }[max_level]
        rules.append(dict(
            id=binary, binary=binary, interpreters=interps,
            allowed_flags=sorted(flags), allowed_flag_prefixes=sorted(prefixes),
            level=max_level, requires_admin=admin, reason=reason,
        ))
    return rules, merges


def write_presets_py(presets):
    lines = []
    lines.append('"""Generated by scripts/generate_command_data.py from the live tool registry.')
    lines.append("")
    lines.append("Each preset is one of the 59 CLI wrappers that used to be its own registered")
    lines.append("tool. Regenerate rather than hand-edit: the risk_level and requires_admin")
    lines.append("fields are the security posture the collapse must preserve exactly.")
    lines.append('"""')
    lines.append("from __future__ import annotations")
    lines.append("")
    lines.append("import re")
    lines.append("from dataclasses import dataclass")
    lines.append("from typing import Dict, List, Optional, Union")
    lines.append("")
    lines.append("")
    lines.append("@dataclass(frozen=True)")
    lines.append("class CommandPreset:")
    lines.append("    id: str")
    lines.append("    summary: str")
    lines.append("    env: Union[str, List[str]]")
    lines.append("    argv_template: List[str]")
    lines.append("    placeholders: List[str]")
    lines.append("    risk_level: str")
    lines.append("    requires_admin: bool")
    lines.append("    probe_binary: str")
    lines.append("    example: str")
    lines.append("    fallback_preset: Optional[str] = None")
    lines.append("    probe_unreliable: bool = False")
    lines.append("")
    lines.append("")
    lines.append("COMMAND_PRESETS: Dict[str, CommandPreset] = {")
    for pid in sorted(presets):
        p = presets[pid]
        lines.append("    %r: CommandPreset(" % pid)
        lines.append("        id=%r," % p["id"])
        lines.append("        summary=%r," % p["summary"])
        lines.append("        env=%r," % (p["env"],))
        lines.append("        argv_template=%r," % (p["argv_template"],))
        lines.append("        placeholders=%r," % (p["placeholders"],))
        lines.append("        risk_level=%r," % p["risk_level"])
        lines.append("        requires_admin=%r," % p["requires_admin"])
        lines.append("        probe_binary=%r," % p["probe_binary"])
        lines.append("        example=%r," % p["example"])
        lines.append("        fallback_preset=%r," % p["fallback_preset"])
        lines.append("        probe_unreliable=%r," % p["probe_unreliable"])
        lines.append("    ),")
    lines.append("}")
    lines.append("")
    lines.append("")
    lines.append("def get_preset(preset_id: str) -> Optional[CommandPreset]:")
    lines.append('    """Return the preset with this id, or None."""')
    lines.append("    return COMMAND_PRESETS.get(preset_id)")
    lines.append("")
    lines.append("")
    lines.append("def list_presets(env: Optional[str] = None) -> List[CommandPreset]:")
    lines.append('    """All presets sorted by id; optionally filtered to one environment."""')
    lines.append("    vals = sorted(COMMAND_PRESETS.values(), key=lambda p: p.id)")
    lines.append("    if env is None:")
    lines.append("        return vals")
    lines.append("    out = []")
    lines.append("    for p in vals:")
    lines.append("        pe = p.env")
    lines.append("        if isinstance(pe, list):")
    lines.append("            if env in pe:")
    lines.append("                out.append(p)")
    lines.append("        elif pe == env:")
    lines.append("            out.append(p)")
    lines.append("    return out")
    lines.append("")
    lines.append("")
    lines.append("def expand_preset(preset_id: str, args: Dict[str, str]) -> List[str]:")
    lines.append('    """Expand a preset to a concrete argv list.')
    lines.append("")
    lines.append("    Security-critical: placeholder values are substituted as argv ELEMENTS")
    lines.append("    only. The result is never re-parsed as a shell string and there is no")
    lines.append("    free-form flags argument. Raises KeyError naming the first missing")
    lines.append("    placeholder (mirrors the old wrapper's 'Missing required tool argument').")
    lines.append('    """')
    lines.append("    preset = COMMAND_PRESETS.get(preset_id)")
    lines.append("    if preset is None:")
    lines.append("        raise KeyError(preset_id)")
    lines.append("    out: List[str] = []")
    lines.append("    for element in preset.argv_template:")
    lines.append("        def _repl(m: 're.Match') -> str:")
    lines.append("            key = m.group(1)")
    lines.append("            if key not in args:")
    lines.append("                raise KeyError(key)")
    lines.append("            return str(args[key])")
    lines.append(r'        out.append(re.sub(r"\{(\w+)\}", _repl, element))')
    lines.append("    return out")
    lines.append("")
    with io.open(PRESETS_PY, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_rules_yaml(rules, merges):
    if not os.path.isdir(POLICY_DIR):
        os.makedirs(POLICY_DIR)
    init_py = os.path.join(POLICY_DIR, "__init__.py")
    if not os.path.exists(init_py):
        with io.open(init_py, "w", encoding="utf-8") as f:
            f.write('"""Command classification policy for the unified shell_exec tool.\n\n'
                    "command_rules.yaml is generated by scripts/generate_command_data.py.\n"
                    'No import-time I/O here; consumers read RULES_PATH themselves.\n"""\n'
                    "from __future__ import annotations\n\n"
                    "import os\n\n"
                    "RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "
                    '"command_rules.yaml")\n')

    out = []
    out.append("# Generated by scripts/generate_command_data.py. Seeded from the 59 CLI-wrapper")
    out.append("# ToolDefinitions so the classifier reproduces their existing risk decisions.")
    out.append("version: 1")
    out.append("rules:")
    for r in sorted(rules, key=lambda x: x["id"]):
        out.append("  - id: %s" % r["id"])
        out.append("    binary: %s" % r["binary"])
        out.append("    interpreters: [%s]" % ", ".join(r["interpreters"]))
        out.append("    allowed_flags: %s" % json.dumps(r["allowed_flags"]))
        out.append("    allowed_flag_prefixes: %s" % json.dumps(r["allowed_flag_prefixes"]))
        out.append("    level: %s" % r["level"])
        out.append("    requires_admin: %s" % ("true" if r["requires_admin"] else "false"))
        out.append("    reason: %s" % json.dumps(r["reason"]))
    out.append("")
    if merges:
        out.append("# ---- merge audit: presets that collapsed onto one binary rule ----")
        for rule_id in sorted(merges):
            out.append("#   %s <= %s" % (rule_id, ", ".join(merges[rule_id])))
    else:
        out.append("# ---- merge audit: no binaries were shared; every rule is 1:1 ----")
    out.append("")
    with io.open(RULES_YAML, "w", encoding="utf-8") as f:
        f.write("\n".join(out))


if __name__ == "__main__":
    main()
