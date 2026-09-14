# CyberTools plugins

Put one plugin per Python file in this directory. `cyber_tools.py` discovers
`.py` files at runtime, so adding a new tool does not require editing
the controller.

## Required plugin shape

```python
from typing import Any, Dict

from cyber_tools import CyberToolPlugin


class ExampleTool(CyberToolPlugin):
    name = "example"
    description = "Explain what the tool does."
    version = "1.0.0"

    def run(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "output": {"received": dict(arguments)},
            "error": "",
        }


TOOL_CLASS = ExampleTool
```

The controller skips files beginning with `_`, including `_tool_template.py`.
Every other `.py` file must expose `TOOL_CLASS`, which must inherit from
`CyberToolPlugin`. A module that fails to import or violates the interface is
reported under `Skipped modules` without blocking valid tools.

## How it works

When `CyberAgent` starts, `register_all_default_tools()` calls the dynamic
loader. Each plugin becomes a regular `ToolDefinition`, so the existing
environment checks, risk guardrails, audit logging, fallback logic, and UI
events still apply.

## Friend-facing caller template

Use `STAI/cyber_tools_template.py` when another script or friend needs to
call tools. It keeps calls inside the normal `CyberAgent` pipeline:

```python
from cyber_tools_template import CyberToolsClient

client = CyberToolsClient()
print(client.list_tools())
print(client.call("hello", {"name": "Analyst"}))
```

The command-line form is:

```bash
python cyber_tools_template.py list
python cyber_tools_template.py call hello --input '{"name": "Analyst"}'
```

## Compatibility

Plugins are cross-platform by default because their `environments` value is
`["cross_platform"]`. A plugin can instead declare `native_windows` or
`wsl_linux`, and the existing registry will decide whether it can run. Tools
that call operating-system commands should use the project's existing command
execution and safety patterns rather than assuming a shell, path format, or
binary exists.

This framework cannot safely import and call literally any Python module
automatically. An arbitrary module may require packages, execute side effects
at import time, expose no predictable function, expect different arguments,
or only work on one operating system. To make a module compatible, wrap it in
a `CyberToolPlugin` class and expose `TOOL_CLASS`, or write an explicit
adapter that validates its inputs and returns the standard result mapping.
That keeps the module compatible with the registry without bypassing the
project's safety controls.

List all tools through the existing registry:

```bash
python -c "from cyber_agent import CyberAgent; print(CyberAgent().registry.list_tools())"
```

Execute a plugin through the existing agent controller:

```python
from cyber_agent import CyberAgent

agent = CyberAgent()
result = agent.execute_tool("hello", {"name": "Analyst"})
print(result)
```