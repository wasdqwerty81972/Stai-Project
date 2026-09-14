"""Friend-facing template for calling tools from the CyberAI project.

This file is intentionally safe to copy and customize. It uses the existing
CyberAgent controller instead of importing tool implementations directly, so
tool calls keep the normal registry lookup, environment routing, guardrails,
audit logging, fallbacks, and UI events.

Run from the STAI directory:

    python cyber_tools_template.py list
    python cyber_tools_template.py call hello --input '{"name": "Analyst"}'

Use this module from another Python script:

    from cyber_tools_template import CyberToolsClient

    client = CyberToolsClient()
    print(client.list_tools())
    print(client.call("hello", {"name": "Analyst"}))
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List, Optional


class CyberToolsClient:
    """Small integration wrapper for friends and external Python scripts."""

    def __init__(self, workspace_path: str = ".") -> None:
        # Import lazily so importing this template does not initialize the
        # full application or require optional desktop dependencies.
        from cyber_agent import CyberAgent

        self.agent = CyberAgent(workspace_path=workspace_path)

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return every registered built-in and dynamically loaded tool."""
        return self.agent.registry.list_tools()

    def call(
        self, tool_name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Call a tool through the existing CyberAgent execution pipeline."""
        return self.agent.execute_tool(tool_name, arguments or {})


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="List and call tools through the CyberAgent controller."
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("list", help="list all registered tools")

    call_parser = subparsers.add_parser("call", help="call one registered tool")
    call_parser.add_argument("tool_name", help="registered tool name")
    call_parser.add_argument(
        "--input",
        default="{}",
        help="tool arguments as a JSON object (default: {})",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Run the template's optional command-line interface."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    client = CyberToolsClient()

    if args.command in (None, "list"):
        print(json.dumps(client.list_tools(), indent=2, default=str))
        return 0

    try:
        arguments = json.loads(args.input)
    except json.JSONDecodeError as exc:
        parser.error(f"--input must be valid JSON: {exc}")
    if not isinstance(arguments, dict):
        parser.error("--input must contain a JSON object")

    result = client.call(args.tool_name, arguments)
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())