HEAD
# Stai-Project
CyberAI Security Suite Documentation

## System Overview
A unified cybersecurity interface integrating:
- Security tools (100+ scanners/analyzers)
- SOC workflow management
- Incident response automation
- AI-enhanced threat analysis

## Core Components
1. **Agent Framework**: Core components including:
   - Tool registry system
   - Risk level enforcement
   - AI integration via KeyManager
2. **UI Framework**: Customtkinter-based interface
   - Agent-first interaction model
   - Three-pane layout design
3. **Security Architecture**: 
   - Multi-layer defense with:
     - Code integrity checks
     - Network monitoring
     - System isolation capabilities

## Technical Requirements
- Windows 10/11 or WSL2-compatible environment
- Python 3.9+ with customtkinter
- PostgreSQL database for findings
- Active Directory integration for corporate deployments

## Threat Intelligence Configuration
Live IOC enrichment (`cyber_threat_intel.py`) is optional and reads two environment
variables. Without them the lookup tools still run, but report `verdict: "unknown"` —
never a clean result.

| Variable | Provider | Get a key |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal | https://www.virustotal.com/gui/my-apikey |
| `OTX_API_KEY` | AlienVault OTX | https://otx.alienvault.com/api |

```bash
setx VIRUSTOTAL_API_KEY "your-key-here"
```

Tools enabled: `virustotal_hash_lookup`, `virustotal_ip_lookup`, `otx_ip_lookup`,
`enrich_artifact`. All are `READ_ONLY` and auto-approve.

Two things to know before enabling them:

- **These lookups leave your network.** The hash or IP you submit is disclosed to a
  third party. Do not enrich artifacts from an environment where that is not permitted.
- **`verdict: "unknown"` means "no data", not "safe."** A missing key, rate limit,
  network failure, or an artifact VirusTotal has never seen all produce `unknown`. Treating
  it as clean reintroduces the false-negative this integration was built to remove.

VirusTotal's free tier allows 4 requests/minute and 500/day. Requests are throttled and
cached for one hour automatically, so repeated lookups of the same artifact are free.

`urlscan_check`, `abuseipdb_check`, and `shodan_lookup` have **no implementation** and
always return `verdict: "unknown"`.

## Usage
1. Launch via `cyber_main.py`
2. Access tools through the chat interface
3. Manage sessions in the sidebar
4. View findings in the dedicated tab

## Dynamic CyberTools Plugins

The project supports drop-in Python tools through the `Tools_cyber` directory.
The existing `cyber_tools.py` module discovers and registers plugin files when
the tool registry is initialized.

### Plugin directory

```text
STAI/
├── cyber_tools.py
├── cyber_tools_template.py
└── Tools_cyber/
    ├── __init__.py
    ├── _tool_template.py
    ├── hello_tool.py
    └── your_new_tool.py
```

### What `Tools_cyber/__init__.py` does

`Tools_cyber/__init__.py` marks the directory as a Python package. It currently
contains only a documentation string:

```python
"""Drop-in CyberTools plugins live in this directory."""
```

It does not register or execute tools. The loader scans the individual Python
files in the directory. You normally do not need to edit `__init__.py` when
adding a tool.

### Required plugin structure

Every discoverable plugin must:

1. Be a `.py` file directly inside `Tools_cyber`
2. Define a class inheriting from `CyberToolPlugin`
3. Provide `name`, `description`, and `version`
4. Implement `run(arguments)`
5. Export the class as `TOOL_CLASS`
6. Return a dictionary containing `success`, `output`, and `error`

Example:

```python
from typing import Any, Dict

from cyber_tools import CyberToolPlugin


class ExampleTool(CyberToolPlugin):
    name = "example"
    description = "An example compatible tool."
    version = "1.0.0"
    environments = ["cross_platform"]

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "output": {"received": dict(arguments)},
            "error": "",
        }


TOOL_CLASS = ExampleTool
```

The easiest way to start is to copy:

```text
Tools_cyber/_tool_template.py
```

Rename the copy to a new filename, change the class and metadata, and
implement the tool logic. Files beginning with `_` are ignored, so the
template itself is not loaded as a tool.

### Discovery process

When `register_all_default_tools()` runs:

1. `cyber_tools.py` resolves the `Tools_cyber` directory relative to itself.
2. It scans direct `.py` files in alphabetical order.
3. Private files beginning with `_` and `__init__.py` are skipped.
4. Each remaining module is imported dynamically with `importlib`.
5. `TOOL_CLASS` is checked to confirm it inherits from `CyberToolPlugin`.
6. The plugin metadata is converted into the existing `ToolDefinition`.
7. The plugin is added to the existing `ToolRegistry`.
8. Calls use the normal `CyberAgent` execution pipeline.

This means dynamically loaded tools receive the same environment checks,
risk-level handling, guardrails, audit logging, fallbacks, and UI events as
built-in tools.

If one plugin fails to import or has invalid metadata, it is reported as an
unavailable optional plugin and the other valid plugins still load. Duplicate
tool names are rejected so a plugin cannot silently replace an existing tool.

### Tool environments

Plugins are cross-platform by default:

```python
environments = ["cross_platform"]
```

For operating-system-specific tools, use the existing environment names:

```python
environments = ["native_windows"]
```

or:

```python
environments = ["wsl_linux"]
```

The registry decides whether the declared environment is available. A plugin
that uses an operating-system command should avoid assuming that a particular
shell, executable, path format, or permission exists.

### Listing and calling tools

The registry exposes all built-in and dynamically loaded tools:

```python
from cyber_agent import CyberAgent

agent = CyberAgent()
for tool in agent.registry.list_tools():
    print(tool)
```

For friends or external Python scripts, use:

```python
from cyber_tools_template import CyberToolsClient

client = CyberToolsClient()

print(client.list_tools())
result = client.call("hello", {"name": "Analyst"})
print(result)
```

The template also provides a command-line interface from the `STAI` directory:

```bash
python cyber_tools_template.py list
python cyber_tools_template.py call hello --input '{"name": "Analyst"}'
```

### Compatibility boundaries

The plugin system is compatible with any Python tool that follows the
`CyberToolPlugin` contract. Standard-library tools are usually easy to keep
cross-platform, while tools using external packages must have those packages
available in the runtime.

The loader does not automatically import and execute arbitrary Python modules.
An arbitrary module may run side effects during import, require missing
packages, expose no predictable function, expect different arguments, or only
work on one operating system. To make an existing module compatible, wrap it
in a `CyberToolPlugin` adapter that validates arguments and returns the
standard result dictionary. This preserves the project's safety controls
instead of bypassing them.

## Security Features
- Dynamic tool routing based on environment
- AI-validated tool execution
- Comprehensive audit logging
- Hardware integrity monitoring
1d51937 (Initial project upload)
